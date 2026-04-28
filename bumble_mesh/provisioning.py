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
    DATA_SENT = 11

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

        # Full PDUs (INCLUDING Type Byte) for ConfirmationInputs
        self.pdu_invite = b''       # 2 bytes
        self.pdu_capabilities = b'' # 12 bytes
        self.pdu_start = b''        # 6 bytes
        self.pdu_pubkey_p = b''     # 65 bytes
        self.pdu_pubkey_device = b'' # 65 bytes

        self.auth_value = b'\x00' * 16
        self.provisioner_random = os.urandom(16)
        self.device_random: Optional[bytes] = None
        self.device_confirmation: Optional[bytes] = None
        self.dev_key: Optional[bytes] = None

    def invite(self, attention_duration: int = 0) -> bytes:
        self.pdu_invite = b'\x00' + bytes([attention_duration])
        self.state = ProvisioningState.INVITE
        return self.pdu_invite

    def set_auth_value(self, auth_value: bytes):
        """Sets the authentication value (e.g. from OOB)."""
        if len(auth_value) != 16:
            raise ValueError("AuthValue must be 16 bytes")
        self.auth_value = auth_value
        # If we have shared_secret, we can move to CONFIRM. Otherwise wait for PubKey.
        if self.shared_secret is not None:
            self.state = ProvisioningState.CONFIRM

    def handle_pdu(self, pdu: bytes, **kwargs) -> Optional[bytes]:
        pdu_type = pdu[0]
        if pdu_type == 0x01: # Capabilities
            return self._handle_capabilities(pdu)
        elif pdu_type == 0x03: # Public Key
            return self._handle_public_key(pdu)
        elif pdu_type == 0x04: # Input Complete
            logger.info("Received Input Complete from device")
            return None
        elif pdu_type == 0x05: # Confirm
            return self._handle_confirm(pdu)
        elif pdu_type == 0x06: # Random
            return self._handle_random(pdu, **kwargs)
        elif pdu_type == 0x08: # Complete
            logger.info("Received Provisioning Complete PDU from device")
            self.state = ProvisioningState.COMPLETE
            return None
        elif pdu_type == 0x09: # Failed
            return self._handle_failed(pdu)
        return None

    def _handle_failed(self, pdu: bytes) -> None:
        error_code = pdu[1] if len(pdu) > 1 else 0
        logger.error(f"Provisioning Failed! Error Code: {error_code:02x}")
        self.state = ProvisioningState.FAILED
        return None

    def _handle_capabilities(self, pdu: bytes) -> Optional[bytes]:
        if self.state != ProvisioningState.INVITE: return None
        self.pdu_capabilities = pdu
        
        # Spec Table 5.37: Provisioning Capabilities
        # pdu[5] is Static OOB Type
        # pdu[6] is Output OOB Size
        # pdu[7:9] is Output OOB Action (2 bytes)
        output_size = pdu[6]
        output_action_mask = int.from_bytes(pdu[7:9], 'big')
        
        if output_size > 0 and (output_action_mask & 0x0008): # 0x0008 = OutputNumeric
            logger.info(f"Device supports OutputNumeric OOB (Size: {output_size})")
            self.auth_method, self.auth_action = 0x02, 0x03 # Output OOB, Numeric
            self.auth_size = output_size
        else:
            logger.info(f"OOB not supported or mask mismatch (Size: {output_size}, Mask: {output_action_mask:04x}). Falling back to No OOB.")
            self.auth_method, self.auth_action, self.auth_size = 0, 0, 0

        self.pdu_start = b'\x02' + bytes([0x00, 0x00, self.auth_method, self.auth_action, self.auth_size])
        self.state = ProvisioningState.PUBLIC_KEY
        return self.pdu_start

    def get_public_key_pdu(self) -> bytes:
        return b'\x03' + self.local_key.x + self.local_key.y

    def _handle_public_key(self, pdu: bytes) -> Optional[bytes]:
        self.pdu_pubkey_device = pdu
        self.remote_public_key_x = pdu[1:33]
        self.remote_public_key_y = pdu[33:65]
        self.shared_secret = self.local_key.dh(self.remote_public_key_x, self.remote_public_key_y)
        logger.info("Device Public Key received and Shared Secret calculated.")
        
        if self.auth_method == 0x00:
            self.state = ProvisioningState.CONFIRM
            return self._send_confirm()
        
        # If OOB, we stay in current state (likely AUTH_INPUT) until PIN arrives
        return None

    def _send_confirm(self) -> bytes:
        # Note: BlueZ excludes opcodes from confirmation inputs
        # 恢复之前的逻辑：剔除第一个字节 (Opcode)
        inputs = self.pdu_invite[1:] + self.pdu_capabilities[1:] + self.pdu_start[1:] + \
                 self.local_key.x + self.local_key.y + self.remote_public_key_x + self.remote_public_key_y
        self.provisioning_salt = s1(inputs)
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        conf_p = aes_cmac(conf_key, self.provisioner_random + self.auth_value)
        return b'\x05' + conf_p

    def _handle_confirm(self, pdu: bytes) -> bytes:
        self.device_confirmation = pdu[1:]
        self.state = ProvisioningState.CHECK
        return b'\x06' + self.provisioner_random

    def _handle_random(self, pdu: bytes, net_key: bytes = b'\x01'*16, iv_index: int = 0, unicast_address: int = 0x0002) -> Optional[bytes]:
        self.device_random = pdu[1:]
        
        # 1. Verification
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        expected_confirm = aes_cmac(conf_key, self.device_random + self.auth_value)
        if expected_confirm != self.device_confirmation:
            logger.error("Confirmation Failed!")
            self.state = ProvisioningState.FAILED
            return None
        
        # 2. Derive Final ProvisioningSalt (Spec v1.0.1 Section 5.4.2.4)
        # ProvisioningSalt = s1(ConfirmationSalt || ProvisionerRandom || DeviceRandom)
        final_salt = s1(self.provisioning_salt + self.provisioner_random + self.device_random)
        logger.info(f"Final ProvisioningSalt derived: {final_salt.hex()}")

        # 3. Derive Session Material using final_salt
        session_key = k1(self.shared_secret, final_salt, b"prsk")
        session_nonce = k1(self.shared_secret, final_salt, b"prsn")[3:16]
        self.dev_key = k1(self.shared_secret, final_salt, b"prdk")
        logger.info(f"DevKey derived successfully.")
        
        # 4. Prepare and Encrypt Provisioning Data
        prov_data = net_key + b'\x00\x00' + b'\x00' + iv_index.to_bytes(4, 'big') + unicast_address.to_bytes(2, 'big')
        encrypted_data = aes_ccm_encrypt(session_key, session_nonce, prov_data, b'', 8)
        
        self.state = ProvisioningState.DATA_SENT
        return b'\x07' + encrypted_data
