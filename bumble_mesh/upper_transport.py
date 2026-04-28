import logging
from .crypto import aes_ccm_decrypt, aes_ccm_encrypt, k2

logger = logging.getLogger(__name__)


def calc_aid(app_key: bytes) -> int:
    """Calculate the Application Key Identifier (AID) from an AppKey.
    The AID is the least significant 6 bits of k2(AppKey, '00')[0].
    Per Mesh Profile Spec v1.0.1 Section 4.2.6.
    """
    aid, _, _ = k2(app_key, b'\x00')
    return aid & 0x3F

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
        BlueZ uses 4-byte MIC for unsegmented messages regardless of AKF.
        For DevKey (akf=0): aszmic=0, mic_len=4 (matching BlueZ msg_rxed behavior)
        """
        nonce_type = 0x01 if akf else 0x02
        aszmic = 0  # BlueZ always uses 4-byte MIC for unsegmented
        mic_len = 4
        
        nonce = self._create_nonce(nonce_type, aszmic, seq, src, dst, iv_index)
        return aes_ccm_encrypt(key, nonce, payload, b'', mic_len)

    def decrypt(self, src: int, dst: int, seq: int, iv_index: int, transport_pdu: bytes, akf: int, aid: int, aszmic: int = 0) -> bytes | None:
        """
        Decrypts an incoming Upper Transport PDU.
        """
        nonce_type = 0x01 if akf else 0x02
        # BlueZ uses 4-byte MIC for unsegmented messages regardless of AKF
        actual_aszmic = aszmic  # Use the provided aszmic (0 for unsegmented)
        mic_len = 8 if actual_aszmic else 4
        
        nonce = self._create_nonce(nonce_type, actual_aszmic, seq, src, dst, iv_index)
        
        key = None
        if akf == 0:
            key = self.dev_keys.get(src)
        else:
            key = list(self.app_keys.values())[0] if self.app_keys else None
            
        if not key:
            return None

        try:
            return aes_ccm_decrypt(key, nonce, transport_pdu, b'', mic_len)
        except Exception as e:
            logger.debug(f"Upper Transport Decryption Failed: {e}")
            return None
