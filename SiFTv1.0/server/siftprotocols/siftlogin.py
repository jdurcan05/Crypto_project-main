#python3

import time
import secrets
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2, HKDF
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp, server_privkey=None):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.timestamp_window = 1  # ±1 second acceptance window
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None
        self.server_privkey = server_privkey  # RSA private key for decrypting temporary key 


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users

    def timestamp(self):
        """Generate timestamp in nanoseconds since Unix epoch"""
        return time.time_ns()

    def validate_timestamp(self, ts, window=None):
        """Validate timestamp is within acceptance window (in seconds)"""
        if window is None:
            window = self.timestamp_window
        curr_ts = time.time_ns()
        # Convert window from seconds to nanoseconds
        window_ns = window * 1_000_000_000
        if abs(curr_ts - ts) > window_ns:
            return False
        return True


    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):

        login_req_str = login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password'] 
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):
        """
        Parse login request with v1.0 format:
        <timestamp>\n<username>\n<password>\n<client_random>
        """
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)

        if len(login_req_fields) != 4:
            raise SiFT_LOGIN_Error('Login request format error: expected 4 fields')

        login_req_struct = {}

        # Parse timestamp
        try:
            login_req_struct['timestamp'] = int(login_req_fields[0])
        except ValueError:
            raise SiFT_LOGIN_Error('Invalid timestamp in login request')

        # Validate timestamp
        if not self.validate_timestamp(login_req_struct['timestamp']):
            raise SiFT_LOGIN_Error('Timestamp validation failed - request too old or too new')

        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]

        # Parse client_random
        try:
            login_req_struct['client_random'] = bytes.fromhex(login_req_fields[3])
        except ValueError:
            raise SiFT_LOGIN_Error('Invalid client_random in login request')

        if len(login_req_struct['client_random']) != 16:
            raise SiFT_LOGIN_Error('Client_random must be 16 bytes')

        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        """
        Build login response with v1.0 format:
        <request_hash>\n<server_random>
        """
        login_res_str = login_res_struct['request_hash'].hex()
        login_res_str += self.delimiter + login_res_struct['server_random'].hex()
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        return login_res_struct


    # derive final transfer key using HKDF
    def derive_transfer_key(self, client_random, server_random, request_hash):
        """
        Derive final transfer key using HKDF-SHA256

        Args:
            client_random: 16-byte client random value
            server_random: 16-byte server random value
            request_hash: 32-byte SHA-256 hash of login request (used as salt)

        Returns:
            32-byte final transfer key
        """
        # IKM = client_random + server_random
        ikm = client_random + server_random

        # Use HKDF with SHA-256 to derive 32-byte final transfer key
        final_key = HKDF(
            master=ikm,
            key_len=32,
            salt=request_hash,
            hashmod=SHA256,
            context=b''  # No context/info field
        )

        return final_key


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False


    # handles login process (to be used by the server)
    def handle_login_server(self):
        """
        Handle server-side login with v1.0 security:
        1. Receive login request with encrypted temporary key (ETK)
        2. Decrypt temporary key using RSA private key
        3. Set temporary key in MTP for decrypting login request
        4. Validate timestamp and credentials
        5. Generate server_random
        6. Derive final transfer key using HKDF
        7. Send login response
        8. Switch from temporary key to final transfer key in MTP
        """

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        if self.server_privkey is None:
            raise SiFT_LOGIN_Error('Server private key not provided')

        # trying to receive a login request
        # Note: MTP returns (msg_type, payload, etk) for login_req messages
        try:
            result = self.mtp.receive_msg()
            if len(result) == 3:
                msg_type, msg_payload, etk = result
            else:
                raise SiFT_LOGIN_Error('Expected ETK in login request but not received')
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # Decrypt temporary key from ETK using RSA-OAEP
        try:
            cipher_rsa = PKCS1_OAEP.new(self.server_privkey)
            temporary_key = cipher_rsa.decrypt(etk)
        except Exception as e:
            raise SiFT_LOGIN_Error('Unable to decrypt temporary key --> ' + str(e))

        if len(temporary_key) != 32:
            raise SiFT_LOGIN_Error('Decrypted temporary key must be 32 bytes')

        # DEBUG
        if self.DEBUG:
            print('Temporary key decrypted: ' + temporary_key.hex()[:32] + '...')
        # DEBUG

        # Set temporary key in MTP (it was already used to decrypt the login request,
        # but we need to set it for sending the login response)
        try:
            self.mtp.set_transfer_key(temporary_key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to set temporary key --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # Parse login request (includes timestamp validation)
        login_req_struct = self.parse_login_req(msg_payload)

        # DEBUG
        if self.DEBUG:
            print('Client random: ' + login_req_struct['client_random'].hex())
        # DEBUG

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unknown user attempted to log in')

        # Generate server_random (16 bytes)
        server_random = secrets.token_bytes(16)

        # DEBUG
        if self.DEBUG:
            print('Server random: ' + server_random.hex())
        # DEBUG

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        login_res_struct['server_random'] = server_random
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # Derive final transfer key using HKDF
        client_random = login_req_struct['client_random']
        final_transfer_key = self.derive_transfer_key(client_random, server_random, request_hash)

        # DEBUG
        if self.DEBUG:
            print('Final transfer key derived: ' + final_transfer_key.hex()[:32] + '...')
        # DEBUG

        # Update MTP with final transfer key for all subsequent messages
        try:
            self.mtp.set_transfer_key(final_transfer_key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to set final transfer key --> ' + e.err_msg)

        # DEBUG
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')