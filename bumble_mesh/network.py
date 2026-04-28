import logging
from .crypto import aes_ccm_encrypt, aes_ccm_decrypt, k2
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

logger = logging.getLogger(__name__)

class NetworkLayer:
    def __init__(self, net_key: bytes, iv_index: int):
        self.net_key = net_key
        self.iv_index = iv_index
        self.seq = 0
        
        # Derive keys
        self.nid, self.encryption_key, self.privacy_key = k2(net_key, b'master')

    def encrypt_pdu(self, src: int, dst: int, transport_pdu: bytes, ctl: int = 0, ttl: int = 4) -> bytes:
        ivi_nid = ((self.iv_index & 1) << 7) | self.nid
        ctl_ttl = (ctl << 7) | (ttl & 0x7F)
        seq_bytes = self.seq.to_bytes(3, 'big')
        src_bytes = src.to_bytes(2, 'big')
        dst_bytes = dst.to_bytes(2, 'big')
        
        header = bytes([ivi_nid, ctl_ttl]) + seq_bytes + src_bytes + dst_bytes
        
        # Nonce: 0x00 || CTL_TTL || SEQ || SRC || Pad(2) || IV Index (4)
        # Mesh Profile Spec v1.0.1 Section 3.8.4.2: Network Nonce type = 0x00
        nonce = bytes([0x00, ctl_ttl]) + seq_bytes + src_bytes + b'\x00\x00' + self.iv_index.to_bytes(4, 'big')
        
        # Encrypt DST + TransportPDU together (matching BlueZ behavior)
        # BlueZ encrypts packet[7:] = DST(2) + TransportPDU(N)
        plaintext = dst_bytes + transport_pdu
        mic_len = 8 if ctl else 4
        encrypted_payload = aes_ccm_encrypt(self.encryption_key, nonce, plaintext, b'', mic_len)

        # Obfuscation (Mesh Spec v1.0.1 Section 3.8.4.3)
        # Privacy Random = encrypted_payload[0:7] (first 7 bytes of encrypted data)
        privacy_random = encrypted_payload[:7]
        iv_index_bytes = self.iv_index.to_bytes(4, 'big')
        
        cipher = Cipher(algorithms.AES(self.privacy_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        # pecb = e(PrivacyKey, 0x0000000000 || IV Index || Privacy Random)
        pecb = encryptor.update(b'\x00' * 5 + iv_index_bytes + privacy_random) + encryptor.finalize()
        
        # Obfuscate CTL_TTL (1) + SEQ (3) + SRC (2) = 6 bytes
        obfuscated = bytes([a ^ b for a, b in zip(header[1:7], pecb[:6])])
        
        pdu = bytes([header[0]]) + obfuscated + encrypted_payload
        logger.debug(f"[TX 网络层] SRC=0x{src:04x} DST=0x{dst:04x} SEQ={self.seq} CTL={ctl} PDU={pdu.hex()}")
        self.seq += 1
        return pdu

    def decrypt_pdu(self, pdu: bytes) -> Optional[tuple]:
        if len(pdu) < 14: return None

        ivi_nid = pdu[0]
        if (ivi_nid & 0x7F) != self.nid: return None

        # De-obfuscate: encrypted payload starts at pdu[7] (DST is encrypted)
        encrypted_payload = pdu[7:]
        # Privacy Random = first 7 bytes of encrypted data
        privacy_random = encrypted_payload[:7]
        
        cipher = Cipher(algorithms.AES(self.privacy_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        pecb = encryptor.update(b'\x00' * 5 + self.iv_index.to_bytes(4, 'big') + privacy_random) + encryptor.finalize()
        
        deobfuscated = bytes([a ^ b for a, b in zip(pdu[1:7], pecb[:6])])
        
        ctl_ttl = deobfuscated[0]
        ctl = ctl_ttl >> 7
        seq_bytes = deobfuscated[1:4]
        src_bytes = deobfuscated[4:6]
        
        src = int.from_bytes(src_bytes, 'big')
        seq = int.from_bytes(seq_bytes, 'big')
        
        nonce = bytes([0x00, ctl_ttl]) + seq_bytes + src_bytes + b'\x00\x00' + self.iv_index.to_bytes(4, 'big')
        
        mic_len = 8 if ctl else 4
        try:
            # DST is encrypted together with TransportPDU (matching BlueZ)
            decrypted = aes_ccm_decrypt(self.encryption_key, nonce, encrypted_payload, b'', mic_len)
            dst = int.from_bytes(decrypted[0:2], 'big')
            transport_pdu = decrypted[2:]
            logger.debug(f"[RX 网络层] 解密成功: 来自=0x{src:04x} 目标=0x{dst:04x} SEQ={seq} CTL={ctl} PDU={pdu.hex()}")
            return src, dst, seq, transport_pdu, ctl
        except Exception:
            return None
