# SiFT v1.0 Implementation Progress

## Overview
This document tracks the implementation of SiFT v1.0 security features, upgrading from v0.5 to v1.0 with full cryptographic protection.

## Implementation Date
Started: 2025-11-17

## Key Changes Required

### 1. MTP (Message Transfer Protocol) Enhancements
**Status: NOT STARTED**

Changes needed:
- [x] Update version from 0.5 to 1.0
- [ ] Expand header from 6 bytes to 16 bytes
- [ ] Add sequence number (sqn) tracking for replay protection
- [ ] Add random field (rnd) generation for nonce
- [ ] Implement AES-GCM encryption for all payloads
- [ ] Implement AES-GCM MAC generation and verification
- [ ] Handle encrypted temporary key (etk) for login requests
- [ ] Implement key management (temporary key → final transfer key)

Files to modify:
- `/SiFTv1.0/client/siftprotocols/siftmtp.py`
- `/SiFTv1.0/server/siftprotocols/siftmtp.py`

### 2. Login Protocol Enhancements - CLIENT
**Status: NOT STARTED**

Changes needed:
- [ ] Add timestamp generation (nanoseconds since epoch)
- [ ] Generate client_random (16 bytes)
- [ ] Generate temporary key (32 bytes AES)
- [ ] Encrypt temporary key with server's RSA public key (RSA-OAEP)
- [ ] Update login request format: `<timestamp>\n<username>\n<password>\n<client_random>`
- [ ] Parse server_random from login response
- [ ] Implement HKDF key derivation for final transfer key
- [ ] Pass final transfer key to MTP layer

Files to modify:
- `/SiFTv1.0/client/siftprotocols/siftlogin.py`

### 3. Login Protocol Enhancements - SERVER
**Status: NOT STARTED**

Changes needed:
- [ ] Load/manage RSA private key
- [ ] Decrypt temporary key from login request (RSA-OAEP)
- [ ] Validate timestamp (acceptance window ~2 seconds)
- [ ] Parse client_random from login request
- [ ] Generate server_random (16 bytes)
- [ ] Update login response format: `<request_hash>\n<server_random>`
- [ ] Implement HKDF key derivation for final transfer key
- [ ] Pass final transfer key to MTP layer

Files to modify:
- `/SiFTv1.0/server/siftprotocols/siftlogin.py`
- `/SiFTv1.0/server/server.py` (for RSA key management)

### 4. Client Main Modifications
**Status: NOT STARTED**

Changes needed:
- [ ] Load server's RSA public key
- [ ] Pass public key to login protocol

Files to modify:
- `/SiFTv1.0/client/client.py`

---

## Current Issues Found

### MTP Files (Both Client and Server)
1. **Line 16-17**: Version still set to 0.5 - needs to be changed to 1.0
2. **Line 18**: `msg_hdr_ver` still `b'\x00\x05'` - needs to be `b'\x01\x00'`
3. **Line 19**: `size_msg_hdr` is 6 - needs to be 16 for v1.0
4. **Line 51-53**: `parse_msg_header()` has bugs (undefined variable 'u', incorrect indexing)
5. **Missing**: No encryption/decryption logic
6. **Missing**: No MAC generation/verification
7. **Missing**: No sequence number tracking
8. **Missing**: No temporary key handling for login requests

### Login Files (Both Client and Server)
1. **Client line 34-35**: `build_login_req()` missing timestamp and client_random
2. **Server line 40-45**: `parse_login_req()` expects only 2 fields (username, password)
3. **Client line 50-52**: `build_login_res()` missing server_random
4. **Both**: No temporary key generation or RSA encryption
5. **Both**: No HKDF key derivation implementation
6. **Both**: No integration with MTP for key management

---

## Implementation Plan

### Phase 1: MTP Layer (Foundation)
1. Fix header parsing bugs
2. Update version to 1.0 and header size to 16 bytes
3. Implement sequence number tracking
4. Implement AES-GCM encryption/decryption
5. Implement MAC generation/verification
6. Add key management interface

### Phase 2: Login Protocol
1. Update message formats (add timestamp, client_random, server_random)
2. Implement temporary key generation (client)
3. Implement RSA-OAEP encryption/decryption
4. Implement HKDF key derivation
5. Add timestamp validation (server)
6. Integrate with MTP key management

### Phase 3: Integration
1. Update client.py to load RSA public key
2. Update server.py to load RSA private key
3. Test end-to-end communication
4. Verify all security properties

---

## Cryptographic Dependencies Required

```python
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Random import get_random_bytes
import time
import secrets
```

---

## Security Properties to Verify

- [x] Confidentiality: AES-GCM encryption
- [ ] Integrity: AES-GCM MAC
- [ ] Authentication (Client): Username/password
- [ ] Authentication (Server): RSA implicit authentication
- [ ] Replay Protection: Sequence numbers + timestamps
- [ ] Forward Secrecy: Session key derivation

---

## Notes

### AES-GCM Parameters
- Key size: 32 bytes (256-bit)
- Nonce: sqn (2 bytes) + rnd (6 bytes) = 8 bytes
- MAC size: 12 bytes
- Additional authenticated data (AAD): entire header (16 bytes)

### RSA Parameters
- Key size: 2048-bit
- Encryption scheme: RSA-OAEP
- Temporary key size: 32 bytes
- Encrypted temporary key size: 256 bytes

### HKDF Parameters
- Hash function: SHA-256
- Input key material: client_random (16 bytes) + server_random (16 bytes)
- Salt: request_hash (32 bytes SHA-256)
- Info: None (or can use protocol identifier)
- Output: 32 bytes (final transfer key)

### Timestamp Validation
- Format: Nanoseconds since Unix epoch
- Acceptance window: ±1 second (configurable)
- Server should track recent timestamps to prevent replay

---

## Testing Checklist

- [ ] Version negotiation works
- [ ] Header parsing correct for all message types
- [ ] Encryption/decryption successful
- [ ] MAC verification catches tampering
- [ ] Sequence numbers prevent replay
- [ ] Timestamp validation works
- [ ] RSA encryption/decryption successful
- [ ] Key derivation produces same key on both sides
- [ ] Login succeeds with correct credentials
- [ ] Login fails with wrong credentials
- [ ] File upload/download works with encryption
- [ ] All commands work correctly

---

## Implementation Log

### 2025-11-17 - Initial Analysis
- Analyzed existing v0.5 implementation
- Identified all required changes
- Created implementation plan
- Documented security requirements

### Next Session
- Begin Phase 1: MTP Layer implementation
