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
    def __init__(self, mtp, server_pubkey=None):

        self.DEBUG = True
        # --------- CONSTANTS ------------
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.timestamp_window = 1  # ±1 second acceptance window
        # --------- STATE ------------
        self.mtp = mtp
        self.server_users = None
        self.server_pubkey = server_pubkey  # RSA public key for encrypting temporary key 


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
        """
        Build login request with v1.0 format:
        <timestamp>\n<username>\n<password>\n<client_random>

        Returns: (payload, client_random, temporary_key, etk)
        """
        # Generate timestamp (nanoseconds since epoch)
        timestamp = self.timestamp()

        # Generate client_random (16 bytes)
        client_random = secrets.token_bytes(16)

        # Generate temporary key (32 bytes for AES-256)
        temporary_key = secrets.token_bytes(32)

        # Build login request payload
        login_req_str = str(timestamp)
        login_req_str += self.delimiter + login_req_struct['username']
        login_req_str += self.delimiter + login_req_struct['password']
        login_req_str += self.delimiter + client_random.hex()

        payload = login_req_str.encode(self.coding)

        # Encrypt temporary key with server's RSA public key using RSA-OAEP
        if self.server_pubkey is None:
            raise SiFT_LOGIN_Error('Server public key not provided')

        cipher_rsa = PKCS1_OAEP.new(self.server_pubkey)
        etk = cipher_rsa.encrypt(temporary_key)

        return payload, client_random, temporary_key, etk


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):

        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        login_req_struct = {}
        login_req_struct['username'] = login_req_fields[0]
        login_req_struct['password'] = login_req_fields[1]
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):

        login_res_str = login_res_struct['request_hash'].hex() 
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        """
        Parse login response with v1.0 format:
        <request_hash>\n<server_random>
        """
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = bytes.fromhex(login_res_fields[1])
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

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

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

        login_req_struct = self.parse_login_req(msg_payload)

        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
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

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password):
        """
        Handle client-side login with v1.0 security:
        1. Generate temporary key and encrypt with server's RSA public key
        2. Send login request with encrypted temporary key (ETK)
        3. Receive login response
        4. Derive final transfer key using HKDF
        5. Switch from temporary key to final transfer key in MTP
        """

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        msg_payload, client_random, temporary_key, etk = self.build_login_req(login_req_struct)

        # DEBUG
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('Temporary key: ' + temporary_key.hex()[:32] + '...')
            print('Client random: ' + client_random.hex())
            print('------------------------------------------')
        # DEBUG

        # Set temporary key in MTP for encrypting the login request
        try:
            self.mtp.set_transfer_key(temporary_key)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to set temporary key --> ' + e.err_msg)

        # trying to send login request with encrypted temporary key
        try:
            self.mtp.send_msg(self.mtp.type_login_req, msg_payload, etk=etk)
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

        # checking request_hash received in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')

        # Derive final transfer key using HKDF
        server_random = login_res_struct['server_random']

        # DEBUG
        if self.DEBUG:
            print('Server random: ' + server_random.hex())
        # DEBUG

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