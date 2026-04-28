#!/usr/bin/env python3
"""Self-test: encrypt with DST, then decrypt. Verifies our crypto chain."""
from bumble_mesh.crypto import k2, aes_ccm_encrypt, aes_ccm_decrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

net_key = b'\x00' * 16
nid, enc_key, priv_key = k2(net_key, b'master')
print(f'NID: 0x{nid:02x}')
print(f'Enc: {enc_key.hex()}')
print(f'Priv: {priv_key.hex()}')

src, dst, seq, ctl, ttl = 0x0001, 0x0002, 0, 0, 4
iv_index = 0
ivi_nid = ((iv_index & 1) << 7) | nid
ctl_ttl = (ctl << 7) | (ttl & 0x7F)
dst_bytes = dst.to_bytes(2, 'big')

# Transport PDU (12 bytes: lower hdr 0x00 + upper 11 bytes)
transport_pdu = bytes([0x00]) + b'\x00' * 11

# === ENCRYPT ===
nonce = (bytes([0x00, ctl_ttl]) +
         seq.to_bytes(3, 'big') +
         src.to_bytes(2, 'big') +
         b'\x00\x00' +
         iv_index.to_bytes(4, 'big'))
plaintext = dst_bytes + transport_pdu
enc = aes_ccm_encrypt(enc_key, nonce, plaintext, b'', 4)
print(f'Enc plain({len(plaintext)}): {plaintext.hex()}')
print(f'Enc cipher({len(enc)}): {enc.hex()}')

# Obfuscate
privacy_random = enc[:7]
ecb = Cipher(algorithms.AES(priv_key), modes.ECB(), backend=default_backend())
pecb = ecb.encryptor().update(
    b'\x00' * 5 + iv_index.to_bytes(4, 'big') + privacy_random
) + ecb.encryptor().finalize()
header = bytes([ivi_nid, ctl_ttl]) + seq.to_bytes(3, 'big') + src.to_bytes(2, 'big') + dst_bytes
obfuscated = bytes([a ^ b for a, b in zip(header[1:7], pecb[:6])])
pdu = bytes([header[0]]) + obfuscated + enc
print(f'PDU({len(pdu)}): {pdu.hex()}')

# === DECRYPT ===
ep = pdu[7:]
pr = ep[:7]
ecb2 = Cipher(algorithms.AES(priv_key), modes.ECB(), backend=default_backend())
pecb2 = ecb2.encryptor().update(
    b'\x00' * 5 + iv_index.to_bytes(4, 'big') + pr
) + ecb2.encryptor().finalize()
deb = bytes([a ^ b for a, b in zip(pdu[1:7], pecb2[:6])])
ctl2 = deb[0] >> 7
seq2 = int.from_bytes(deb[1:4], 'big')
src2 = int.from_bytes(deb[4:6], 'big')
nonce2 = (bytes([0x00, deb[0]]) +
          deb[1:4] +
          deb[4:6] +
          b'\x00\x00' +
          iv_index.to_bytes(4, 'big'))
dec = aes_ccm_decrypt(enc_key, nonce2, ep, b'', 4)
dst2 = int.from_bytes(dec[0:2], 'big')
tpd2 = dec[2:]
print(f'\nDECRYPT: SRC=0x{src2:04x} DST=0x{dst2:04x} SEQ={seq2}')
print(f'Transport match: {tpd2 == transport_pdu}')
print(f'DST correct: {dst2 == dst}')
print(f'SRC correct: {src2 == src}')
print(f'\nNonce enc: {nonce.hex()}')
print(f'Nonce dec: {nonce2.hex()}')
print(f'Nonces match: {nonce == nonce2}')
