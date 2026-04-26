import asyncio
import logging
import sys
import os
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.bearer import AdvBearer
from bumble_mesh.crypto import crc8, s1, k1, aes_cmac, aes_ccm_decrypt
from bumble.crypto import EccKey

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

class MeshDeviceSimulator:
    def __init__(self, device, uuid: bytes):
        self.device = device
        self.uuid = uuid
        self.bearer = AdvBearer(device)
        self.link_id = 0
        self.is_linked = False
        self.local_key = EccKey.generate()
        self.remote_pub_key = None
        self.shared_secret = None
        self.provisioning_salt = None
        
        # PDU Log for Confirm verification
        self.pdu_invite = b''
        self.pdu_capabilities = b''
        self.pdu_start = b''
        self.pdu_pubkey_provisioner = b''
        self.pdu_pubkey_device = b''

        self.device_random = os.urandom(16)
        self.provisioner_random = None
        self.auth_value = b'\x00' * 16

    async def start(self):
        self.bearer.on_pdu = self._on_pdu
        await self.bearer.start()
        
        # Start broadcasting Unprovisioned Beacon
        asyncio.create_task(self._broadcast_beacon())
        logger.info(f"Mesh Simulator active. UUID: {self.uuid.hex()}")

    async def _broadcast_beacon(self):
        """Broadcast Unprovisioned Device Beacon every 2 seconds."""
        beacon_data = b'\x00' + self.uuid + b'\x00\x00' # Type 0x00, UUID, OOB
        while not self.is_linked:
            # Send using ad_type 0x2B (Mesh Beacon)
            await self.bearer.send_pdu(beacon_data, is_pb_adv=True) # Logic in bearer handles type
            await asyncio.sleep(2.0)

    def _on_pdu(self, pdu):
        if len(pdu) < 6: return
        link_id = int.from_bytes(pdu[0:4], 'big')
        trans_num = pdu[4]
        gpc_byte = pdu[5]

        # 1. Handle Link Open
        if (gpc_byte & 0x03) == 0x03:
            opcode = gpc_byte >> 2
            if opcode == 0x03: # Open Req
                logger.info(f"Received Link Open from ID: {link_id:08x}")
                self.link_id = link_id
                self.is_linked = True
                # Send Link ACK (0x07)
                asyncio.create_task(self.bearer.send_pdu(pdu[0:4] + b'\x00\x07'))
        
        # 2. Handle Data Transactions
        elif (gpc_byte & 0x03) == 0x00: # Transaction Start
            # ACK it immediately
            asyncio.create_task(self.bearer.send_pdu(pdu[0:4] + bytes([trans_num, 0x01])))
            
            payload = pdu[9:] # Skip header
            self._handle_provisioning_pdu(payload)

    def _handle_provisioning_pdu(self, pdu):
        pdu_type = pdu[0]
        logger.info(f"RX Provisioning PDU Type: 0x{pdu_type:02x}")

        if pdu_type == 0x00: # Invite
            self.pdu_invite = pdu
            # Send Capabilities
            self.pdu_capabilities = bytes([
                0x01, # Type
                0x01, # Elements
                0x00, 0x01, # Algos (FIPS P-256)
                0x00, # PubKey Type
                0x00, # Static OOB
                0x00, 0x00, 0x00, # Output OOB
                0x00, 0x00, 0x00  # Input OOB
            ])
            self._send_trans(self.pdu_capabilities)

        elif pdu_type == 0x02: # Start
            self.pdu_start = pdu
            logger.info("Provisioning Started.")

        elif pdu_type == 0x03: # Public Key
            self.pdu_pubkey_provisioner = pdu
            # Calculate Shared Secret
            px = pdu[1:33]
            py = pdu[33:65]
            self.shared_secret = self.local_key.dh(px, py)
            
            # Send Device Public Key
            self.pdu_pubkey_device = bytes([0x03]) + self.local_key.x + self.local_key.y
            self._send_trans(self.pdu_pubkey_device)

        elif pdu_type == 0x05: # Confirm
            prov_confirm = pdu[1:]
            # 1. Calc Salt
            inputs = self.pdu_invite + self.pdu_capabilities + self.pdu_start + \
                     self.pdu_pubkey_provisioner + self.pdu_pubkey_device
            self.provisioning_salt = s1(inputs)
            
            # 2. Send Device Confirm
            conf_key = k1(self.shared_secret, self.provisioning_salt, b"prck")
            dev_confirm = aes_cmac(self.device_random + self.auth_value, conf_key)
            self._send_trans(bytes([0x05]) + dev_confirm)

        elif pdu_type == 0x06: # Random
            self.provisioner_random = pdu[1:]
            # Send Device Random
            self._send_trans(bytes([0x06]) + self.device_random)

        elif pdu_type == 0x07: # Data
            logger.info("Received Provisioning Data! NetKey exchange start.")
            # Session Keys
            session_key = k1(self.shared_secret, self.provisioning_salt, b"prsk")
            session_nonce = k1(self.shared_secret, self.provisioning_salt, b"prsn")[3:16]
            
            try:
                decrypted = aes_ccm_decrypt(session_key, session_nonce, pdu[1:], b'', 8)
                logger.info(f"SUCCESS! Decrypted NetKey: {decrypted[:16].hex()}")
                logger.info(f"Assigned Address: {decrypted[23:25].hex()}")
                # Send Complete
                self._send_trans(bytes([0x08]))
            except Exception as e:
                logger.error(f"Failed to decrypt provisioning data: {e}")

    def _send_trans(self, pdu):
        # Simplified: Non-segmented send back for simulator
        header = self.link_id.to_bytes(4, 'big') + bytes([0x00, 0x00, 0x00, len(pdu), crc8(pdu)])
        # Actually needs proper TransNum from Provisioner. Simplified for test.
        asyncio.create_task(self.bearer.send_pdu(header + pdu))

async def main():
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:0'
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            device = Device.with_hci('Mesh-Device-Sim', '00:00:00:11:22:33', hci_source, hci_sink)
            await device.power_on()
            
            sim = MeshDeviceSimulator(device, bytes.fromhex("11223344556677889900AABBCCDDEEFF"))
            await sim.start()
            await asyncio.get_event_loop().create_future()
    except Exception as e:
        logger.error(f"Sim Error: {e}")

if __name__ == '__main__':
    asyncio.run(main())
