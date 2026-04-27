import asyncio
import enum
import os
import logging
from typing import Optional, Callable
from .crypto import s1, k1, aes_cmac, aes_ccm_encrypt
from bumble.crypto import EccKey

logger = logging.getLogger(__name__)

class ProvisioningState(enum.Enum):
    IDLE = 0
    INVITE = 1
    CAPABILITIES = 2
    START = 3
    PUBLIC_KEY = 4
    AUTH_INPUT = 5
    CONFIRM = 6
    CHECK = 7
    DATA = 8
    COMPLETE = 9
    FAILED = 10

class ProvisioningSession:
    def __init__(self, role: str = 'provisioner'):
        self.role = role
        self.state = ProvisioningState.IDLE
        self.local_key = EccKey.generate()
        self.remote_public_key_x: Optional[bytes] = None
        self.remote_public_key_y: Optional[bytes] = None
        self.shared_secret: Optional[bytes] = None
        self.provisioning_salt: Optional[bytes] = None
        
        # OOB Selection
        self.auth_method = 0
        self.auth_action = 0
        self.auth_size = 0

        # Exact Payloads (EXCLUDING Type Byte) for ConfirmationInputs
        self.payload_invite = b''       # 1 byte
        self.payload_capabilities = b'' # 11 bytes
        self.payload_start = b''        # 5 bytes
        self.payload_pubkey_p = b''     # 64 bytes
        self.payload_pubkey_device = b'' # 64 bytes

        self.auth_value = b'\x00' * 16
        self.provisioner_random = os.urandom(16)
        self.device_random: Optional[bytes] = None
        self.device_confirmation: Optional[bytes] = None

    def invite(self, attention_duration: int = 0) -> bytes:
        self.payload_invite = bytes([attention_duration])
        self.state = ProvisioningState.INVITE
        return b'\x00' + self.payload_invite

    def set_auth_value(self, auth_value: bytes):
        """Sets the authentication value (e.g. from OOB)."""
        if len(auth_value) != 16:
            raise ValueError("AuthValue must be 16 bytes")
        self.auth_value = auth_value
        if self.state == ProvisioningState.AUTH_INPUT:
            self.state = ProvisioningState.CONFIRM

    def handle_pdu(self, pdu: bytes, **kwargs) -> Optional[bytes]:
        pdu_type = pdu[0]
        if pdu_type == 0x01: # Capabilities
            return self._handle_capabilities(pdu)
        elif pdu_type == 0x03: # Public Key
            return self._handle_public_key(pdu)
        elif pdu_type == 0x05: # Confirm
            return self._handle_confirm(pdu)
        elif pdu_type == 0x06: # Random
            return self._handle_random(pdu, **kwargs)
        elif pdu_type == 0x09: # Failed
            return self._handle_failed(pdu)
        return None

    def _handle_failed(self, pdu: bytes) -> None:
        error_code = pdu[1] if len(pdu) > 1 else 0
        logger.error(f"Provisioning Failed! Error Code: {error_code:02x}")
        self.state = ProvisioningState.FAILED
        return None

    def _handle_capabilities(self, pdu: bytes) -> Optional[bytes]:
        # Idempotency check: If we already processed capabilities, ignore duplicates
        if self.state != ProvisioningState.INVITE:
            return None

        # pdu is [0x01, data(11)]
        self.payload_capabilities = pdu[1:]
        
        # Capability Mapping (Strictly aligned with BlueZ 5.86 / Mesh v1.0)
        # BlueZ sends these fields in Little Endian and expects Action codes:
        # 0x03: Output Numeric  (Bit 3 in mask)
        # 0x04: Output Alpha    (Bit 4 in mask)
        output_size = self.payload_capabilities[5]
        # Parse mask as little-endian to match BlueZ's link->caps[6] byte-check logic
        output_action_mask = int.from_bytes(self.payload_capabilities[6:8], 'little')
        
        if output_size > 0:
            if output_action_mask & 0x0008: # Bit 3: Output Numeric
                logger.info(f"Device supports OutputNumeric OOB (Size: {output_size})")
                self.auth_method = 0x02 
                self.auth_action = 0x03 # BlueZ v1.0 Digit Action
                self.auth_size = output_size
            elif output_action_mask & 0x0010: # Bit 4: Output Alphanumeric
                logger.info(f"Device supports OutputAlphanumeric OOB (Size: {output_size})")
                self.auth_method = 0x02
                self.auth_action = 0x04 # BlueZ v1.0 Alpha Action
                self.auth_size = output_size
            else:
                logger.info("Device has Output OOB but no supported actions, falling back to No OOB")
                self.auth_method = 0x00
                self.auth_action = 0x00
                self.auth_size = 0x00
        else:
            logger.info("Using No OOB authentication")
            self.auth_method = 0x00
            self.auth_action = 0x00
            self.auth_size = 0x00

        # Construct Start Payload (5 bytes)
        self.payload_start = bytes([0x00, 0x00, self.auth_method, self.auth_action, self.auth_size])
        logger.info(f"Sending PROV_START: {self.payload_start.hex()} (Method={self.auth_method}, Action={self.auth_action}, Size={self.auth_size})")
        self.state = ProvisioningState.PUBLIC_KEY
        return b'\x02' + self.payload_start

    def get_public_key_pdu(self) -> bytes:
        self.payload_pubkey_p = self.local_key.x + self.local_key.y
        return b'\x03' + self.payload_pubkey_p

    def _handle_public_key(self, pdu: bytes) -> Optional[bytes]:
        # pdu is [0x03, X(32), Y(32)]
        self.payload_pubkey_device = pdu[1:]
        self.remote_public_key_x = pdu[1:33]
        self.remote_public_key_y = pdu[33:65]
        
        self.shared_secret = self.local_key.dh(self.remote_public_key_x, self.remote_public_key_y)
        
        if self.auth_method != 0x00:
            logger.info("Authentication Required. Waiting for User Input...")
            self.state = ProvisioningState.AUTH_INPUT
            return None # Pause and wait for set_auth_value
        
        self.state = ProvisioningState.CONFIRM
        return self._send_confirm()

    def _send_confirm(self) -> bytes:
        # Inputs = Invite(1) || Caps(11) || Start(5) || PubP(64) || PubD(64) = 145 bytes
        inputs = self.payload_invite + self.payload_capabilities + self.payload_start + \
                 self.payload_pubkey_p + self.payload_pubkey_device
        
        logger.debug(f"ConfirmationInputs: {inputs.hex()}")
        self.provisioning_salt = s1(inputs)
        
        # ConfirmationKey = k1(SharedSecret, ProvSalt, "prck")
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        
        # Confirm = AES-CMAC(ConfKey, RandomP || AuthValue)
        conf_p = aes_cmac(conf_key, self.provisioner_random + self.auth_value)
        return b'\x05' + conf_p

    def _handle_confirm(self, pdu: bytes) -> bytes:
        self.device_confirmation = pdu[1:]
        self.state = ProvisioningState.CHECK
        return b'\x06' + self.provisioner_random

    def _handle_random(self, pdu: bytes, net_key: bytes = b'\x01'*16, iv_index: int = 0, unicast_address: int = 0x0002) -> Optional[bytes]:
        self.device_random = pdu[1:]
        
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        expected_confirm = aes_cmac(conf_key, self.device_random + self.auth_value)
        
        if expected_confirm != self.device_confirmation:
            logger.error(f"Confirmation Failed! Expected: {expected_confirm.hex()}, Got: {self.device_confirmation.hex()}")
            self.state = ProvisioningState.FAILED
            return None
            
        # Provisioning Data
        session_key = k1(self.shared_secret, self.provisioning_salt, b"prsk")
        session_nonce = k1(self.shared_secret, self.provisioning_salt, b"prsn")[3:16]
        
        # Data: NetKey(16) || Index(2) || Flags(1) || IV(4) || Addr(2) = 25 bytes
        prov_data = net_key + b'\x00\x00' + b'\x00' + \
                    iv_index.to_bytes(4, 'big') + unicast_address.to_bytes(2, 'big')
        
        encrypted_data = aes_ccm_encrypt(session_key, session_nonce, prov_data, b'', 8)
        self.state = ProvisioningState.COMPLETE
        return b'\x07' + encrypted_data
