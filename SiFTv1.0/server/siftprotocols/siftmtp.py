#python3

import socket
import secrets
from Crypto.Cipher import AES
from Crypto.Hash import SHA256


class SiFT_MTP_Error(Exception):
    """Exception class for MTP errors"""
    def __init__(self, err_msg):
        self.err_msg = err_msg


class SiFT_MTP:
    """
    SiFT v1.0 Message Transfer Protocol implementation

    This class handles:
    - Message encryption using AES-GCM
    - Message authentication using MAC tags
    - Replay protection using sequence numbers
    - Key management for temporary and final transfer keys
    """

    def __init__(self, peer_socket):
        """Initialize MTP with a peer socket connection"""

        self.DEBUG = True

        #CONSTANTS
        self.version_major = 1
        self.version_minor = 0
        self.msg_hdr_ver = b'\x01\x00'  # v1.0 header

        # Header field sizes for v1.0 (16-byte header total)
        self.size_msg_hdr = 16
        self.size_msg_hdr_ver = 2
        self.size_msg_hdr_typ = 2
        self.size_msg_hdr_len = 2
        self.size_msg_hdr_sqn = 2 
        self.size_msg_hdr_rnd = 6  
        self.size_msg_hdr_rsv = 2 

        # MAC (authentication tag) size for AES-GCM
        self.size_msg_mac = 12

        # Encrypted temporary key size (RSA-2048 produces 256 bytes)
        self.size_msg_etk = 256

        # Message type constants
        self.type_login_req =    b'\x00\x00'
        self.type_login_res =    b'\x00\x10'
        self.type_command_req =  b'\x01\x00'
        self.type_command_res =  b'\x01\x10'
        self.type_upload_req_0 = b'\x02\x00'
        self.type_upload_req_1 = b'\x02\x01'
        self.type_upload_res =   b'\x02\x10'
        self.type_dnload_req =   b'\x03\x00'
        self.type_dnload_res_0 = b'\x03\x10'
        self.type_dnload_res_1 = b'\x03\x11'
        self.msg_types = (
            self.type_login_req, self.type_login_res,
            self.type_command_req, self.type_command_res,
            self.type_upload_req_0, self.type_upload_req_1, self.type_upload_res,
            self.type_dnload_req, self.type_dnload_res_0, self.type_dnload_res_1
        )

        # --------- STATE ------------
        self.peer_socket = peer_socket

        # Sequence number tracking for replay protection
        self.sqn_send = 0
        self.sqn_receive = 0

        # Key management:
        # - temporary_key: Used for login messages (login_req, login_res)
        # - transfer_key: Used for all post-login messages (commands, uploads, downloads)
        self.temporary_key = None
        self.transfer_key = None


    def set_transfer_key(self, key):
        """
        Set the transfer key for AES-GCM encryption/decryption

        Args:
            key: 32-byte AES key (either temporary or final transfer key)
        """
        if len(key) != 32:
            raise SiFT_MTP_Error('Transfer key must be 32 bytes')
        self.transfer_key = key

        if self.DEBUG:
            print(f'Transfer key set: {key.hex()[:32]}...')


    def parse_msg_header(self, msg_hdr):
        """
        Parse a 16-byte v1.0 message header into a dictionary

        Header format:
        - ver (2 bytes): Protocol version
        - typ (2 bytes): Message type
        - len (2 bytes): Total message length
        - sqn (2 bytes): Sequence number
        - rnd (6 bytes): Random value for nonce
        - rsv (2 bytes): Reserved

        Args:
            msg_hdr: 16-byte header as bytes

        Returns:
            Dictionary with parsed header fields
        """
        parsed_msg_hdr = {}
        i = 0

        # Parse version (2 bytes)
        parsed_msg_hdr['ver'] = msg_hdr[i:i+self.size_msg_hdr_ver]
        i += self.size_msg_hdr_ver

        # Parse type (2 bytes)
        parsed_msg_hdr['typ'] = msg_hdr[i:i+self.size_msg_hdr_typ]
        i += self.size_msg_hdr_typ

        # Parse length (2 bytes)
        parsed_msg_hdr['len'] = msg_hdr[i:i+self.size_msg_hdr_len]
        i += self.size_msg_hdr_len

        # Parse sequence number (2 bytes)
        parsed_msg_hdr['sqn'] = msg_hdr[i:i+self.size_msg_hdr_sqn]
        i += self.size_msg_hdr_sqn

        # Parse random value (6 bytes)
        parsed_msg_hdr['rnd'] = msg_hdr[i:i+self.size_msg_hdr_rnd]
        i += self.size_msg_hdr_rnd

        # Parse reserved field (2 bytes)
        parsed_msg_hdr['rsv'] = msg_hdr[i:i+self.size_msg_hdr_rsv]

        return parsed_msg_hdr


    def receive_bytes(self, n):
        """
        Receive exactly n bytes from the peer socket

        Args:
            n: Number of bytes to receive

        Returns:
            Received bytes

        Raises:
            SiFT_MTP_Error: If unable to receive or connection broken
        """
        bytes_received = b''
        bytes_count = 0

        while bytes_count < n:
            try:
                chunk = self.peer_socket.recv(n - bytes_count)
            except:
                raise SiFT_MTP_Error('Unable to receive via peer socket')

            if not chunk:
                raise SiFT_MTP_Error('Connection with peer is broken')

            bytes_received += chunk
            bytes_count += len(chunk)

        return bytes_received


    def receive_msg(self):
        """
        Receive and decrypt a v1.0 MTP message

        Process:
        1. Receive 16-byte header
        2. Parse header and validate version/type
        3. Receive encrypted payload + MAC (+ ETK for login_req)
        4. Verify sequence number for replay protection
        5. Decrypt and verify MAC using AES-GCM
        6. Update receive sequence number

        Returns:
            Tuple of (msg_type, decrypted_payload) or (msg_type, payload, etk) for login_req

        Raises:
            SiFT_MTP_Error: On any error in reception, parsing, or decryption
        """

        #Receive header
        try:
            msg_hdr = self.receive_bytes(self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

        if len(msg_hdr) != self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message header received')

        #Parse and validate header
        parsed_msg_hdr = self.parse_msg_header(msg_hdr)

        if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
            raise SiFT_MTP_Error('Unsupported version found in message header')

        if parsed_msg_hdr['typ'] not in self.msg_types:
            raise SiFT_MTP_Error('Unknown message type found in message header')

        # Extract sequence number and random value
        msg_sqn = int.from_bytes(parsed_msg_hdr['sqn'], byteorder='big')
        msg_rnd = parsed_msg_hdr['rnd']
        msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
        msg_type = parsed_msg_hdr['typ']

        #Receive message body (encrypted payload + MAC)
        try:
            msg_body = self.receive_bytes(msg_len - self.size_msg_hdr)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)

        # DEBUG output
        if self.DEBUG:
            print('MTP message received (' + str(msg_len) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('BDY (' + str(len(msg_body)) + '): ' + msg_body.hex()[:128] + '...')
            print('------------------------------------------')

        if len(msg_body) != msg_len - self.size_msg_hdr:
            raise SiFT_MTP_Error('Incomplete message body received')

        # The received sqn must be greater than the last received sqn
        if msg_sqn <= self.sqn_receive:
            raise SiFT_MTP_Error(f'Sequence number error: received {msg_sqn}, expected > {self.sqn_receive}')

        #Decrypt and verify using AES-GCM
        if self.transfer_key is None:
            raise SiFT_MTP_Error('Transfer key not set, cannot decrypt message')

        # Extract encrypted payload and MAC
        if msg_type == self.type_login_req:
            if len(msg_body) < self.size_msg_mac + self.size_msg_etk:
                raise SiFT_MTP_Error('Login request message body too short')
            epd_length = len(msg_body) - self.size_msg_mac - self.size_msg_etk
            epd = msg_body[:epd_length]
            mac = msg_body[epd_length:epd_length + self.size_msg_mac]
            etk = msg_body[epd_length + self.size_msg_mac:]
        else:
            if len(msg_body) < self.size_msg_mac:
                raise SiFT_MTP_Error('Message body too short')
            epd = msg_body[:-self.size_msg_mac]
            mac = msg_body[-self.size_msg_mac:]
            etk = None

        # Construct nonce: sqn (2 bytes) + rnd (6 bytes) = 8 bytes
        nonce = parsed_msg_hdr['sqn'] + msg_rnd

        # Create AES-GCM cipher for decryption
        cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)

        # Add header as additional authenticated data (AAD)
        cipher.update(msg_hdr)

        # Decrypt and verify
        try:
            payload = cipher.decrypt_and_verify(epd, mac)
        except ValueError as e:
            raise SiFT_MTP_Error('MAC verification failed - message authentication error')

        #Update receive sequence number
        self.sqn_receive = msg_sqn

        # Return message type, decrypted payload, and ETK (if present)
        if etk:
            return msg_type, payload, etk
        else:
            return msg_type, payload


    def send_bytes(self, bytes_to_send):
        """
        Send all bytes via the peer socket

        Args:
            bytes_to_send: Bytes to send

        Raises:
            SiFT_MTP_Error: If unable to send
        """
        try:
            self.peer_socket.sendall(bytes_to_send)
        except:
            raise SiFT_MTP_Error('Unable to send via peer socket')


    def send_msg(self, msg_type, msg_payload, etk=None):
        """
        Encrypt and send a v1.0 MTP message

        Process:
        1. Increment send sequence number
        2. Generate random value for nonce
        3. Build header with sqn and rnd
        4. Encrypt payload using AES-GCM with nonce = sqn + rnd
        5. Generate MAC over header + encrypted payload
        6. Send: header + encrypted_payload + MAC (+ ETK for login_req)

        Args:
            msg_type: Message type (2 bytes)
            msg_payload: Plaintext payload to encrypt and send
            etk: Encrypted temporary key (256 bytes, only for login_req)

        Raises:
            SiFT_MTP_Error: If unable to send or transfer key not set
        """

        if self.transfer_key is None:
            raise SiFT_MTP_Error('Transfer key not set, cannot send message')

        #Increment sequence number
        self.sqn_send += 1
        sqn_bytes = self.sqn_send.to_bytes(self.size_msg_hdr_sqn, byteorder='big')

        #Generate random value (6 bytes) using cryptographic RNG
        rnd_bytes = secrets.token_bytes(self.size_msg_hdr_rnd)

        #Construct nonce from sqn + rnd
        nonce = sqn_bytes + rnd_bytes

        #Create AES-GCM cipher for encryption
        cipher = AES.new(self.transfer_key, AES.MODE_GCM, nonce=nonce, mac_len=self.size_msg_mac)

        # Calculate message size
        if etk:
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac + self.size_msg_etk
        else:
            msg_size = self.size_msg_hdr + len(msg_payload) + self.size_msg_mac

        msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
        rsv_bytes = b'\x00\x00'  # Reserved field

        #Construct complete header
        msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + sqn_bytes + rnd_bytes + rsv_bytes

        # Add header as additional authenticated data (AAD)
        cipher.update(msg_hdr)

        #Encrypt payload and generate MAC
        epd, mac = cipher.encrypt_and_digest(msg_payload)

        #Build complete message
        if etk:
            complete_msg = msg_hdr + epd + mac + etk
        else:
            complete_msg = msg_hdr + epd + mac

        # DEBUG output
        if self.DEBUG:
            print('MTP message to send (' + str(msg_size) + '):')
            print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
            print('EPD (' + str(len(epd)) + '): ' + epd.hex()[:128] + '...')
            print('MAC (' + str(len(mac)) + '): ' + mac.hex())
            if etk:
                print('ETK (' + str(len(etk)) + '): ' + etk.hex()[:64] + '...')
            print('------------------------------------------')

        #Send message
        try:
            self.send_bytes(complete_msg)
        except SiFT_MTP_Error as e:
            raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)
