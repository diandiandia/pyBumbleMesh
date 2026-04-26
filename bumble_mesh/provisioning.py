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
        
        self.pdu_invite = b''
        self.pdu_capabilities = b''
        self.pdu_start = b''
        self.pdu_pubkey_provisioner = b''
        self.pdu_pubkey_device = b''

        self.auth_value = b'\x00' * 16
        self.provisioner_random = os.urandom(16)
        self.device_random: Optional[bytes] = None
        self.device_confirmation: Optional[bytes] = None

    def invite(self, attention_duration: int = 0) -> bytes:
        # PROV_INVITE (Opcode 0x00): Total 2 bytes
        self.pdu_invite = bytes([0x00, attention_duration])
        self.state = ProvisioningState.INVITE
        return self.pdu_invite

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
        return None

    def _handle_capabilities(self, pdu: bytes) -> bytes:
        # PROV_CAPS (Opcode 0x01): Total 12 bytes
        # If the received PDU is not 12 bytes, it's technically invalid but we log it
        if len(pdu) != 12:
            logger.warning(f"Received Capabilities PDU with unexpected length: {len(pdu)}")
        self.pdu_capabilities = pdu
        
        # Send PROV_START (Opcode 0x02): Total 6 bytes
        # Algorithm(1), PublicKey(1), AuthMethod(1), AuthAction(1), AuthSize(1)
        self.pdu_start = bytes([0x02, 0x00, 0x00, 0x00, 0x00, 0x00])
        self.state = ProvisioningState.PUBLIC_KEY
        return self.pdu_start

    def get_public_key_pdu(self) -> bytes:
        # PROV_PUB_KEY (Opcode 0x03): Total 65 bytes (1 + 32 + 32)
        self.pdu_pubkey_provisioner = bytes([0x03]) + self.local_key.x + self.local_key.y
        return self.pdu_pubkey_provisioner

    def _handle_public_key(self, pdu: bytes) -> bytes:
        self.pdu_pubkey_device = pdu
        self.remote_public_key_x = pdu[1:33]
        self.remote_public_key_y = pdu[33:65]
        self.shared_secret = self.local_key.dh(self.remote_public_key_x, self.remote_public_key_y)
        self.state = ProvisioningState.CONFIRM
        return self._send_confirm()

    def _send_confirm(self) -> bytes:
        # PROV_CONFIRM (Opcode 0x05): Total 17 bytes
        inputs = self.pdu_invite + self.pdu_capabilities + self.pdu_start + \
                 self.pdu_pubkey_provisioner + self.pdu_pubkey_device
        self.provisioning_salt = s1(inputs)
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        conf_p = aes_cmac(self.provisioner_random + self.auth_value, conf_key)
        return bytes([0x05]) + conf_p

    def _handle_confirm(self, pdu: bytes) -> bytes:
        self.device_confirmation = pdu[1:]
        self.state = ProvisioningState.CHECK
        # PROV_RANDOM (Opcode 0x06): Total 17 bytes
        return bytes([0x06]) + self.provisioner_random

    def _handle_random(self, pdu: bytes, net_key: bytes = b'\x01'*16, iv_index: int = 0, unicast_address: int = 0x0002) -> Optional[bytes]:
        self.device_random = pdu[1:]
        conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
        expected_confirm = aes_cmac(self.device_random + self.auth_value, conf_key)
        
        if expected_confirm != self.device_confirmation:
            logger.error("Provisioning Confirmation Failed!")
            self.state = ProvisioningState.FAILED
            return None
            
        session_key = k1(self.shared_secret, self.provisioning_salt, b"prsk")
        session_nonce = k1(self.shared_secret, self.provisioning_salt, b"prsn")[3:16]
        
        # PROV_DATA (Opcode 0x07): Total 34 bytes (1 byte opcode + 25 bytes data + 8 bytes MIC)
        prov_data = net_key + b'\x00\x00' + b'\x00' + \
                    iv_index.to_bytes(4, 'big') + unicast_address.to_bytes(2, 'big')
        
        encrypted_data = aes_ccm_encrypt(session_key, session_nonce, prov_data, b'', 8)
        self.state = ProvisioningState.COMPLETE
        return bytes([0x07]) + encrypted_data
