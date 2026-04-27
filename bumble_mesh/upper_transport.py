import logging
from .crypto import aes_ccm_decrypt, aes_ccm_encrypt

logger = logging.getLogger(__name__)

class UpperTransportLayer:
    """
    Handles encryption/decryption of Access PDUs.
    Supports Device Nonce (DevKey) and Application Nonce (AppKey).
    """
    def __init__(self):
        self.app_keys: dict[int, bytes] = {} # index -> key
        self.dev_keys: dict[int, bytes] = {} # address -> key

    def add_app_key(self, index: int, key: bytes):
        self.app_keys[index] = key

    def add_dev_key(self, address: int, key: bytes):
        self.dev_keys[address] = key

    def get_dev_key(self, address: int) -> bytes | None:
        return self.dev_keys.get(address)

    def get_app_key(self, index: int) -> bytes | None:
        return self.app_keys.get(index)

    def _create_nonce(self, nonce_type: int, aszmic: int, seq: int, src: int, dst: int, iv_index: int) -> bytes:
        """
        Mesh Spec Nonce Construction.
        Types: 0x01 (App), 0x02 (Device), 0x03 (Proxy)
        """
        # [0]: Type
        # [1]: ASZMIC (1 bit) || Pad (7 bits)
        # [2-4]: Seq
        # [5-6]: SRC
        # [7-8]: DST
        # [9-12]: IV Index
        first_byte = (aszmic << 7) & 0x80
        nonce = bytes([nonce_type, first_byte]) + \
                seq.to_bytes(3, 'big') + \
                src.to_bytes(2, 'big') + \
                dst.to_bytes(2, 'big') + \
                iv_index.to_bytes(4, 'big')
        return nonce

    def encrypt(self, src: int, dst: int, seq: int, iv_index: int, payload: bytes, key: bytes, akf: int, aid: int = 0) -> bytes:
        """
        Encrypts an Access PDU.
        akf=0: Use Device Nonce (0x02)
        akf=1: Use Application Nonce (0x01)
        """
        nonce_type = 0x01 if akf else 0x02
        nonce = self._create_nonce(nonce_type, 0, seq, src, dst, iv_index)
        
        # Access PDU TransMIC is 4 bytes
        return aes_ccm_encrypt(key, nonce, payload, b'', 4)

    def decrypt(self, src: int, dst: int, seq: int, iv_index: int, transport_pdu: bytes, akf: int, aid: int) -> bytes | None:
        """
        Decrypts an incoming Upper Transport PDU.
        """
        nonce_type = 0x01 if akf else 0x02
        nonce = self._create_nonce(nonce_type, 0, seq, src, dst, iv_index)
        
        key = None
        if akf == 0:
            key = self.dev_keys.get(src)
        else:
            # Simplified: finding app key by AID requires a database lookup
            # For now, we only support one AppKey
            key = list(self.app_keys.values())[0] if self.app_keys else None
            
        if not key:
            return None

        try:
            return aes_ccm_decrypt(key, nonce, transport_pdu, b'', 4)
        except Exception as e:
            logger.debug(f"Upper Transport Decryption Failed: {e}")
            return None
