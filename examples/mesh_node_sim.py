"""
Full Mesh Node Simulator for testing pyBumbleMesh.

This simulates a Bluetooth Mesh node that:
1. Broadcasts Unprovisioned Device Beacon (can be scanned by pyBumbleMesh)
2. Completes PB-ADV provisioning
3. After provisioning, acts as a Mesh node in the network
4. Handles Configuration messages (Composition Get, AppKey Add, Model App Bind)
5. Handles Generic OnOff Get/Set

Usage:
  python -m examples.mesh_node_sim [hci-socket:N]

Run on a separate machine/adapter alongside pyBumbleMesh's mesh_manager.py
"""

import asyncio
import logging
import sys
import os
import struct
from typing import Optional, Callable

from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.bearer import AdvBearer
from bumble_mesh.crypto import crc8, s1, k1, k2, aes_cmac, aes_ccm_decrypt, aes_ccm_encrypt
from bumble.crypto import EccKey

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)


class SimMeshNode:
    """
    A simulated Bluetooth Mesh node that can be provisioned by pyBumbleMesh
    and then handle both config and application messages.
    """

    MODEL_CONFIG_SERVER = 0x0000
    MODEL_REMOTE_PROV_SERVER = 0x0004
    MODEL_PRIV_BEACON_SERVER = 0x0008
    MODEL_GEN_ONOFF_SERVER = 0x1000

    # Config opcodes we handle
    OP_DEV_COMP_GET = 0x8008
    OP_DEV_COMP_STATUS = 0x02
    OP_APPKEY_ADD = 0x00
    OP_APPKEY_STATUS = 0x8003
    OP_MODEL_APP_BIND = 0x803D
    OP_MODEL_APP_STATUS = 0x803E

    # Generic OnOff opcodes
    OP_GEN_ONOFF_GET = 0x8201
    OP_GEN_ONOFF_SET = 0x8202
    OP_GEN_ONOFF_STATUS = 0x8204

    def __init__(self, device, uuid: bytes):
        self.device = device
        self.uuid = uuid
        self.bearer = AdvBearer(device)

        # --- Provisioning state ---
        self.link_id = 0
        self.is_linked = False
        self.is_provisioned = False
        self.local_ecc = EccKey.generate()
        self.remote_pub_key = None
        self.shared_secret = None
        self.provisioning_salt = None
        self.device_random = os.urandom(16)
        self.provisioner_random = None

        # PDU logs for confirmation
        self.pdu_invite = b''
        self.pdu_capabilities = b''
        self.pdu_start = b''
        self.pdu_pubkey_provisioner = b''
        self.pdu_pubkey_device = b''

        # Auth
        self.auth_value = b'\x00' * 16

        # --- Mesh network state (set after provisioning) ---
        self.unicast_addr = 0x0000
        self.net_key = b'\x00' * 16
        self.iv_index = 0
        self.seq = 0
        self.nid = 0
        self.encryption_key = b'\x00' * 16
        self.privacy_key = b'\x00' * 16
        self.dev_key = b'\x00' * 16
        self.app_keys: dict[int, bytes] = {}    # app_key_index -> key
        self.app_key_bindings: dict[int, set] = {}  # model_id -> set of app_key_indices

        # OnOff state
        self.onoff_state = 0

    async def start(self):
        self.bearer.on_pdu = self._on_bearer_pdu
        await self.bearer.start()
        asyncio.create_task(self._broadcast_beacon())
        logger.info(f"Mesh Node Simulator started. UUID: {self.uuid.hex()}")

    async def _broadcast_beacon(self):
        """Broadcast Unprovisioned Device Beacon every 2 seconds (while not provisioned)."""
        while not self.is_provisioned:
            beacon = b'\x00' + self.uuid + b'\x00\x00'
            await self.bearer.send_pdu(beacon, is_pb_adv=True)
            await asyncio.sleep(2.0)

    # ===================== Bearer / PB-ADV =====================

    def _on_bearer_pdu(self, pdu: bytes):
        if self.is_provisioned:
            self._handle_mesh_pdu(pdu)
        else:
            self._handle_pbadv_pdu(pdu)

    def _handle_pbadv_pdu(self, pdu: bytes):
        if len(pdu) < 6:
            return
        link_id = int.from_bytes(pdu[0:4], 'big')
        trans_num = pdu[4]
        gpc_byte = pdu[5]
        gpc_type = gpc_byte & 0x03

        if gpc_type == 0x03:  # Link Control
            opcode = gpc_byte >> 2
            if opcode == 0x03:  # Link Open
                device_uuid = pdu[6:]
                if len(device_uuid) >= 16 and device_uuid[:16] == self.uuid:
                    logger.info(f"Link Open from ID={link_id:08x}")
                    self.link_id = link_id
                    self.is_linked = True
                    asyncio.create_task(self.bearer.send_pdu(pdu[:4] + b'\x00\x07'))
            elif opcode == 0x02:  # Link Close
                reason = pdu[6] if len(pdu) > 6 else 0x00
                logger.info(f"Link Close (reason={reason:02x})")
                self.is_linked = False
                asyncio.create_task(self.bearer.send_pdu(pdu[:4] + b'\x00\x0b'))
            return

        if gpc_type == 0x00:  # Transaction Start
            seg_n = gpc_byte >> 2
            total_len = int.from_bytes(pdu[6:8], 'big')
            fcs = pdu[8]
            payload = pdu[9:9 + total_len]
            if crc8(payload) == fcs:
                asyncio.create_task(self.bearer.send_pdu(pdu[:4] + bytes([trans_num, 0x01])))
                self._handle_provisioning_pdu(payload)
            return

    def _send_trans(self, pdu: bytes):
        """Send a provisioning transaction via PB-ADV."""
        hdr = self.link_id.to_bytes(4, 'big')
        trans_num = (self.seq & 0xFF)
        self.seq += 1
        fcs = crc8(pdu)
        # Unsegmented send
        pkt = hdr + bytes([trans_num, 0x00, 0x00, len(pdu), fcs]) + pdu
        asyncio.create_task(self.bearer.send_pdu(pkt, is_pb_adv=True))

    # ===================== Provisioning Protocol =====================

    def _handle_provisioning_pdu(self, pdu: bytes):
        pdu_type = pdu[0]
        logger.info(f"Provisioning RX type=0x{pdu_type:02x}")

        if pdu_type == 0x00:  # Invite
            self.pdu_invite = pdu
            self.pdu_capabilities = bytes([
                0x01,  # Type Capabilities
                0x02,  # Num Elements (2)
                0x00, 0x01,  # Algos (FIPS P-256)
                0x00,  # PubKey Type
                0x00,  # Static OOB
                0x08,  # Output OOB Size (8 digits)
                0x00, 0x08,  # Output OOB Action (Output Numeric)
                0x00, 0x00,  # Input OOB Size
            ])
            self._send_trans(self.pdu_capabilities)

        elif pdu_type == 0x02:  # Start
            self.pdu_start = pdu
            self.auth_method = pdu[3]
            self.auth_action = pdu[4]
            self.auth_size = pdu[5]
            logger.info(f"Provisioning Start: method={self.auth_method} action={self.auth_action} size={self.auth_size}")

        elif pdu_type == 0x03:  # Public Key (Provisioner)
            self.pdu_pubkey_provisioner = pdu
            px = pdu[1:33]
            py = pdu[33:65]
            self.shared_secret = self.local_ecc.dh(px, py)
            self.pdu_pubkey_device = bytes([0x03]) + self.local_ecc.x + self.local_ecc.y
            self._send_trans(self.pdu_pubkey_device)

            # For Output OOB, generate a random PIN and show it
            if self.auth_method == 0x02 and self.auth_action == 0x03:
                pin = int.from_bytes(os.urandom(4), 'big') % (10 ** self.auth_size)
                print(f"\n*** PIN (display on device): {pin:0{self.auth_size}d} ***\n")
                self.auth_value = pin.to_bytes(16, 'big')

        elif pdu_type == 0x05:  # Confirm (Provisioner)
            prov_confirm = pdu[1:]
            inputs = (self.pdu_invite[1:] + self.pdu_capabilities[1:] +
                      self.pdu_start[1:] +
                      self.pdu_pubkey_provisioner[1:33] + self.pdu_pubkey_provisioner[33:65] +
                      self.pdu_pubkey_device[1:33] + self.pdu_pubkey_device[33:65])
            self.provisioning_salt = s1(inputs)

            conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
            dev_confirm = aes_cmac(conf_key, self.device_random + self.auth_value)
            self._send_trans(bytes([0x05]) + dev_confirm)

        elif pdu_type == 0x06:  # Random (Provisioner)
            self.provisioner_random = pdu[1:]
            self._send_trans(bytes([0x06]) + self.device_random)

        elif pdu_type == 0x07:  # Provisioning Data
            final_salt = s1(self.provisioning_salt + self.provisioner_random + self.device_random)
            session_key = k1(self.shared_secret, final_salt, b"prsk")
            session_nonce = k1(self.shared_secret, final_salt, b"prsn")[3:16]
            self.dev_key = k1(self.shared_secret, final_salt, b"prdk")

            try:
                data = aes_ccm_decrypt(session_key, session_nonce, pdu[1:], b'', 8)
                self.net_key = data[:16]
                key_index = int.from_bytes(data[16:18], 'big')
                flags = data[18]
                self.iv_index = int.from_bytes(data[19:23], 'big')
                self.unicast_addr = int.from_bytes(data[23:25], 'big')
                logger.info(f"Provisioned! Addr=0x{self.unicast_addr:04x} NetKey={self.net_key.hex()}")

                # Derive network keys
                self.nid, self.encryption_key, self.privacy_key = k2(self.net_key, b'\x00')
                logger.info(f"NID=0x{self.nid:02x}")

                self._send_trans(bytes([0x08]))  # Complete
                self.is_provisioned = True
                self.is_linked = False

                logger.info("Provisioning Complete! Entering Mesh network mode.")
                logger.info(f"Device Key: {self.dev_key.hex()}")

            except Exception as e:
                logger.error(f"Provisioning Data decrypt failed: {e}")
                self._send_trans(bytes([0x09, 0x01]))  # Failed

    # ===================== Mesh Network Layer =====================

    def _handle_mesh_pdu(self, pdu: bytes):
        if len(pdu) < 14:
            return

        ivi_nid = pdu[0]
        if (ivi_nid & 0x7F) != self.nid:
            return

        encrypted_payload = pdu[7:]
        privacy_random = encrypted_payload[:7]

        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

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
            decrypted = aes_ccm_decrypt(self.encryption_key, nonce, encrypted_payload, b'', mic_len)
            dst = int.from_bytes(decrypted[0:2], 'big')
            transport_pdu = decrypted[2:]

            # Check if addressed to us or a group we belong to
            if dst != self.unicast_addr and dst != 0x0001 and dst != 0x0000 and not (dst >= 0xC000):
                return

            if ctl == 1:
                # Control message (Segment ACK etc) - handle if needed
                return

            self._handle_transport_pdu(src, dst, seq, transport_pdu)

        except Exception as e:
            logger.debug(f"Net decrypt failed: {e}")

    # ===================== Upper Transport =====================

    def _create_device_nonce(self, aszmic: int, seq: int, src: int, dst: int) -> bytes:
        n = bytes([0x02, (aszmic << 7) & 0x80]) + \
            seq.to_bytes(3, 'big') + \
            src.to_bytes(2, 'big') + \
            dst.to_bytes(2, 'big') + \
            self.iv_index.to_bytes(4, 'big')
        return n

    def _create_app_nonce(self, aszmic: int, seq: int, src: int, dst: int) -> bytes:
        n = bytes([0x01, (aszmic << 7) & 0x80]) + \
            seq.to_bytes(3, 'big') + \
            src.to_bytes(2, 'big') + \
            dst.to_bytes(2, 'big') + \
            self.iv_index.to_bytes(4, 'big')
        return n

    def _handle_transport_pdu(self, src: int, dst: int, seq: int, transport_pdu: bytes):
        if len(transport_pdu) < 1:
            return

        h0 = transport_pdu[0]
        is_segmented = (h0 & 0x80) != 0
        akf = (h0 >> 6) & 1

        if is_segmented:
            if len(transport_pdu) < 4:
                return
            h1, h2, h3 = transport_pdu[1], transport_pdu[2], transport_pdu[3]
            aszmic = (h1 >> 7) & 1
            seg_o = ((h2 & 0x03) << 3) | (h3 >> 5)
            seg_n = h3 & 0x1F
            # For simplicity, assume unsegmented or already reassembled by external SAR layer
            payload = transport_pdu[4:]
        else:
            aszmic = 1 if akf == 0 else 0
            payload = transport_pdu[1:]

        mic_len = 8 if aszmic else 4
        encrypted_payload = payload

        if akf == 0:
            # DevKey
            nonce = self._create_device_nonce(aszmic, seq, src, dst)
            key = self.dev_key
        else:
            # AppKey - try all bound AppKeys
            nonce = self._create_app_nonce(aszmic, seq, src, dst)
            key = None

        try:
            access_pdu = aes_ccm_decrypt(key, nonce, encrypted_payload, b'', mic_len)
            self._handle_access_pdu(src, dst, access_pdu, akf)
        except Exception:
            if akf == 1:
                # Try all AppKeys
                for app_idx, app_key in self.app_keys.items():
                    try:
                        access_pdu = aes_ccm_decrypt(app_key, nonce, encrypted_payload, b'', mic_len)
                        self._handle_access_pdu(src, dst, access_pdu, akf)
                        return
                    except Exception:
                        continue
            logger.debug(f"Upper Transport decrypt failed (AKF={akf}, szmic={aszmic}, from={src:04x})")

    # ===================== Access Layer =====================

    def _handle_access_pdu(self, src: int, dst: int, access_pdu: bytes, akf: int):
        if len(access_pdu) < 1:
            return

        first_byte = access_pdu[0]
        if (first_byte & 0x80) == 0:
            opcode = first_byte
            params = access_pdu[1:]
        elif (first_byte & 0xC0) == 0x80:
            opcode = int.from_bytes(access_pdu[:2], 'big')
            params = access_pdu[2:]
        else:
            opcode = int.from_bytes(access_pdu[:3], 'big')
            params = access_pdu[3:]

        logger.info(f"Access RX opcode=0x{opcode:04x} from={src:04x} params={params.hex()}")

        if opcode == self.OP_DEV_COMP_GET:
            self._handle_comp_get(src)
        elif opcode == self.OP_APPKEY_ADD:
            self._handle_appkey_add(src, params)
        elif opcode == self.OP_MODEL_APP_BIND:
            self._handle_model_app_bind(src, params)
        elif opcode in (self.OP_GEN_ONOFF_GET, self.OP_GEN_ONOFF_SET):
            self._handle_onoff(src, opcode, params)

    # ===================== Model Handlers =====================

    def _send_access_pdu(self, dst: int, opcode: int, params: bytes, akf: int = 0, app_key: bytes = None):
        """Send an access-layer message."""
        if opcode < 0x80:
            access_pdu = bytes([opcode]) + params
        elif opcode < 0x10000:
            access_pdu = opcode.to_bytes(2, 'big') + params
        else:
            access_pdu = opcode.to_bytes(3, 'big') + params

        seq = self.seq
        self.seq += 1
        aszmic = 0
        mic_len = 4

        if akf == 0:
            nonce = self._create_device_nonce(aszmic, seq, self.unicast_addr, dst)
            key = self.dev_key
        else:
            nonce = self._create_app_nonce(aszmic, seq, self.unicast_addr, dst)
            key = app_key or list(self.app_keys.values())[0] if self.app_keys else self.dev_key

        encrypted = aes_ccm_encrypt(key, nonce, access_pdu, b'', mic_len)

        # Build transport PDU
        h0 = ((akf & 1) << 6) | (0 & 0x3F)  # AID=0
        transport_pdu = bytes([h0]) + encrypted

        # Send via network layer
        self._send_mesh_pdu(dst, transport_pdu)

    def _send_mesh_pdu(self, dst: int, transport_pdu: bytes):
        """Send a PDU through the mesh network layer."""
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend

        ivi_nid = ((self.iv_index & 1) << 7) | self.nid
        ctl_ttl = (0 << 7) | 4  # CTL=0, TTL=4
        seq_bytes = self.seq.to_bytes(3, 'big')
        src_bytes = self.unicast_addr.to_bytes(2, 'big')
        dst_bytes = dst.to_bytes(2, 'big')
        self.seq += 1

        nonce = bytes([0x00, ctl_ttl]) + seq_bytes + src_bytes + b'\x00\x00' + self.iv_index.to_bytes(4, 'big')
        plaintext = dst_bytes + transport_pdu
        encrypted = aes_ccm_encrypt(self.encryption_key, nonce, plaintext, b'', 4)

        privacy_random = encrypted[:7]
        cipher = Cipher(algorithms.AES(self.privacy_key), modes.ECB(), backend=default_backend())
        encryptor = cipher.encryptor()
        pecb = encryptor.update(b'\x00' * 5 + self.iv_index.to_bytes(4, 'big') + privacy_random) + encryptor.finalize()

        header = bytes([ivi_nid, ctl_ttl]) + seq_bytes + src_bytes
        obfuscated = bytes([a ^ b for a, b in zip(header[1:7], pecb[:6])])
        pdu = bytes([header[0]]) + obfuscated + encrypted

        asyncio.create_task(self.bearer.send_pdu(pdu, is_pb_adv=False))

    def _handle_comp_get(self, src: int):
        """Handle Composition Data Get - build and send composition data."""
        # Page 0 composition data:
        # CID(2) PID(2) VID(2) CRPL(2) Features(2)
        # Element 0: Loc(2) NumS(1) NumV(1) [SIG models...] [Vendor models...]
        # Element 1: Loc(2) NumS(1) NumV(1) [SIG models...]

        data = bytearray()
        # CID=0x05F1, PID=0x0001, VID=0x0001, CRPL=0x7FFF
        data += struct.pack('<HHHH', 0x05F1, 0x0001, 0x0001, 0x7FFF)
        data += struct.pack('<H', 0x0000)  # Features: relay=0, proxy=0, friend=0, lpn=0

        # Element 0: loc=0x0000
        elem0_models_sig = [self.MODEL_CONFIG_SERVER, self.MODEL_REMOTE_PROV_SERVER,
                           self.MODEL_PRIV_BEACON_SERVER, self.MODEL_GEN_ONOFF_SERVER]
        data += struct.pack('<HBB', 0x0000, len(elem0_models_sig), 1)
        for m in elem0_models_sig:
            data += struct.pack('<H', m)
        data += struct.pack('<I', 0x000105F1)  # Vendor model

        # Element 1: loc=0x0000, just Generic OnOff Client
        elem1_models_sig = [0x1001]
        data += struct.pack('<HBB', 0x0000, len(elem1_models_sig), 0)
        for m in elem1_models_sig:
            data += struct.pack('<H', m)

        # Send as DevKey encrypted (unsegmented or segmented depending on size)
        comp_pdu = bytes([0x00]) + bytes(data)  # Page 0
        self._send_access_pdu(src, self.OP_DEV_COMP_STATUS, comp_pdu, akf=0)

    def _handle_appkey_add(self, src: int, params: bytes):
        """Handle AppKey Add - store the AppKey."""
        if len(params) < 19:
            logger.warning("AppKey Add: short payload")
            return

        net_key_index = int.from_bytes(params[0:2], 'little') & 0xFFF
        app_key_index = (int.from_bytes(params[1:3], 'little') >> 4) & 0xFFF
        app_key = params[3:19]

        logger.info(f"AppKey Add: idx={app_key_index} key={app_key.hex()}")

        self.app_keys[app_key_index] = app_key

        # Build status response
        status = 0x00  # Success
        b0 = net_key_index & 0xFF
        b1 = ((net_key_index >> 8) & 0x0F) | ((app_key_index << 4) & 0xF0)
        b2 = (app_key_index >> 4) & 0xFF
        status_pdu = bytes([status, b0, b1, b2])

        self._send_access_pdu(src, self.OP_APPKEY_STATUS, status_pdu, akf=0)
        logger.info(f"AppKey {app_key_index} added. AID will be {app_key[15] & 0x7F:02x}")

    def _handle_model_app_bind(self, src: int, params: bytes):
        """Handle Model App Bind - bind AppKey to a model."""
        if len(params) < 5:
            return

        element_addr = int.from_bytes(params[0:2], 'little')
        app_key_index = int.from_bytes(params[2:4], 'little') & 0xFFF

        if len(params) >= 6:
            model_id = int.from_bytes(params[4:6], 'little')
        else:
            model_id = int.from_bytes(params[4:8], 'little')

        logger.info(f"Model App Bind: elem={element_addr:04x} app_idx={app_key_index} model=0x{model_id:04x}")

        if model_id not in self.app_key_bindings:
            self.app_key_bindings[model_id] = set()
        self.app_key_bindings[model_id].add(app_key_index)

        # Status response
        status = 0x00
        status_pdu = bytes([status]) + params
        self._send_access_pdu(src, self.OP_MODEL_APP_STATUS, status_pdu, akf=0)

    def _handle_onoff(self, src: int, opcode: int, params: bytes):
        """Handle Generic OnOff Get/Set."""
        if opcode == self.OP_GEN_ONOFF_GET:
            logger.info(f"OnOff Get from {src:04x}, state={self.onoff_state}")
            status_pdu = bytes([self.onoff_state, 0x00, 0x00])
            # Use the first AppKey bound to OnOff Server, or DevKey if none
            akf = 1 if 0x1000 in self.app_key_bindings and self.app_keys else 0
            app_key = None
            if akf:
                idx = list(self.app_key_bindings[0x1000])[0]
                app_key = self.app_keys.get(idx)
            self._send_access_pdu(src, self.OP_GEN_ONOFF_STATUS, status_pdu, akf=akf, app_key=app_key)

        elif opcode == self.OP_GEN_ONOFF_SET:
            if len(params) >= 1:
                new_state = params[0] & 1
                old_state = self.onoff_state
                self.onoff_state = new_state
                logger.info(f"OnOff Set from {src:04x}: {old_state} -> {new_state}")

                # Send status response with remaining time = 0
                status_pdu = bytes([new_state, 0x00, 0x00])
                akf = 1 if 0x1000 in self.app_key_bindings and self.app_keys else 0
                app_key = None
                if akf:
                    idx = list(self.app_key_bindings[0x1000])[0]
                    app_key = self.app_keys.get(idx)
                self._send_access_pdu(src, self.OP_GEN_ONOFF_STATUS, status_pdu, akf=akf, app_key=app_key)


async def main():
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:0'

    uuid = bytes.fromhex("AABBCCDDEEFF00112233445566778899")

    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            device = Device.with_hci('Mesh-Node-Sim', '00:00:00:11:22:33', hci_source, hci_sink)
            await device.power_on()

            sim = SimMeshNode(device, uuid)
            await sim.start()
            await asyncio.get_event_loop().create_future()
    except Exception as e:
        logger.error(f"Error: {e}")


if __name__ == '__main__':
    asyncio.run(main())
