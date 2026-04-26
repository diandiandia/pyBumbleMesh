from .crypto import aes_ccm_encrypt, aes_ccm_decrypt, k2
from typing import Optional
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        
        # Nonce: 0x01 || CTL_TTL || SEQ || SRC || Pad(2) || IV Index (4)
        nonce = bytes([0x01, ctl_ttl]) + seq_bytes + src_bytes + b'\x00\x00' + self.iv_index.to_bytes(4, 'big')
        
        mic_len = 8 if ctl else 4
        encrypted_payload = aes_ccm_encrypt(self.encryption_key, nonce, transport_pdu, b'', mic_len)
        
        # Obfuscation
        # Privacy Random: DST || Encrypted Payload[0:3]
        privacy_random = dst_bytes + encrypted_payload[:3]
        iv_index_bytes = self.iv_index.to_bytes(4, 'big')
        
        cipher = Cipher(algorithms.AES(self.privacy_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        pecb = encryptor.update(b'\x00' * 5 + iv_index_bytes + privacy_random)
        
        # Obfuscate CTL_TTL (1) + SEQ (3) + SRC (2) = 6 bytes
        obfuscated = bytes([a ^ b for a, b in zip(header[1:7], pecb[:6])])
        
        pdu = bytes([header[0]]) + obfuscated + header[7:9] + encrypted_payload
        self.seq += 1
        return pdu

    def decrypt_pdu(self, pdu: bytes) -> Optional[tuple]:
        if len(pdu) < 14: return None
        
        ivi_nid = pdu[0]
        if (ivi_nid & 0x7F) != self.nid: return None
        
        # De-obfuscate
        dst_bytes = pdu[7:9]
        encrypted_payload = pdu[9:]
        privacy_random = dst_bytes + encrypted_payload[:3]
        
        cipher = Cipher(algorithms.AES(self.privacy_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        pecb = encryptor.update(b'\x00' * 5 + self.iv_index.to_bytes(4, 'big') + privacy_random)
        
        deobfuscated = bytes([a ^ b for a, b in zip(pdu[1:7], pecb[:6])])
        
        ctl_ttl = deobfuscated[0]
        ctl = ctl_ttl >> 7
        seq_bytes = deobfuscated[1:4]
        src_bytes = deobfuscated[4:6]
        
        src = int.from_bytes(src_bytes, 'big')
        dst = int.from_bytes(dst_bytes, 'big')
        
        nonce = bytes([0x01, ctl_ttl]) + seq_bytes + src_bytes + b'\x00\x00' + self.iv_index.to_bytes(4, 'big')
        
        mic_len = 8 if ctl else 4
        try:
            transport_pdu = aes_ccm_decrypt(self.encryption_key, nonce, encrypted_payload, b'', mic_len)
            return src, dst, transport_pdu
        except Exception:
            return None
