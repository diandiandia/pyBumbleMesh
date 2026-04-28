import asyncio
import logging
import random
import time
from .bearer import AdvBearer
from .network import NetworkLayer
from .transport import LowerTransportLayer
from .access import AccessLayer
from .pb_adv import PBAdvLink
from .provisioning import ProvisioningSession, ProvisioningState
from .config_manager import MeshConfigManager
from .models.config import ConfigClient
from .models.generic_onoff import GenericOnOffClient
from .models.remote_provisioning import RemoteProvisioningClient
from .pb_remote import PBRemoteLink
from .upper_transport import UpperTransportLayer
from .storage import MeshStorage

logger = logging.getLogger(__name__)

class MeshStack:
    def __init__(self, device, net_key: bytes, unicast_address: int, db_path: str = "mesh_database.db"):
        self.storage = MeshStorage(db_path)
        self.unicast_address = int(self.storage.get_setting("unicast_address", unicast_address))
        self.storage.set_setting("unicast_address", self.unicast_address)
        
        networks = self.storage.get_networks()
        if not networks:
            self.storage.save_network(0, net_key, 0)
            self.net_key = net_key
            self.iv_index = 0
        else:
            self.net_key = networks[0]['key']
            self.iv_index = networks[0]['iv_index']

        self.network = NetworkLayer(self.net_key, iv_index=self.iv_index)
        self.network.seq = int(self.storage.get_setting("seq", 0))
        
        self.bearer = AdvBearer(device)
        self.upper_transport = UpperTransportLayer()
        # Load keys from storage
        for ak in self.storage.get_app_keys():
            self.upper_transport.add_app_key(ak['index'], ak['key'])
        for node in self.storage.get_nodes():
            self.upper_transport.add_dev_key(node['address'], node['dev_key'])
            
        self.transport = LowerTransportLayer()
        self.access = AccessLayer()
        self.config_manager = MeshConfigManager(self)
        
        # --- REGISTER MODELS ---
        self.config_client = self.config_manager.config_client # Re-use from manager
        self.onoff_client = GenericOnOffClient()
        self.rp_client = RemoteProvisioningClient()
        self.access.register_model(self.onoff_client)
        self.access.register_model(self.rp_client)
        
        self.provisioning_sessions = {} 
        self.provisioning_states = {} 

        self.bearer.on_pdu = self._on_bearer_pdu
        self.bearer.on_unprovisioned_device = self._on_unprovisioned_device

    async def remote_provision_device(self, server_addr: int, uuid: bytes):
        """Provisions a device via a Remote Provisioning Server node."""
        nodes = self.storage.get_nodes()
        next_addr = self.unicast_address + 1
        if nodes: next_addr = max(n['address'] for n in nodes) + 1
            
        # Create a Remote Tunnel Link instead of PB-ADV
        pb_link = PBRemoteLink(self, server_addr, self.rp_client)
        link_id = random.getrandbits(32) # For internal tracking
        self.provisioning_sessions[link_id] = pb_link
        
        success = await pb_link.open(uuid)
        if not success: return
        
        session = ProvisioningSession()
        self.provisioning_states[link_id] = session
        
        pdu_queue = asyncio.Queue()

        async def pdu_worker():
            while True:
                pdu = await pdu_queue.get()
                try:
                    if session.state in (ProvisioningState.FAILED, ProvisioningState.COMPLETE): break
                    resp = session.handle_pdu(pdu, net_key=self.net_key, iv_index=self.iv_index, unicast_address=next_addr)
                    
                    if resp:
                        await pb_link.send_transaction(resp)

                    if session.state == ProvisioningState.COMPLETE:
                        logger.info(f"Remote Provisioning Successful! Node Address: {next_addr:04x}")
                        self.storage.save_node(next_addr, uuid, session.shared_secret)
                        self.upper_transport.add_dev_key(next_addr, session.shared_secret)
                        asyncio.create_task(self.config_manager.configure_node(next_addr, 0, b'\x02'*16))
                        break
                except Exception as e: logger.error(f"Remote Worker Error: {e}")
                finally: pdu_queue.task_done()

        worker_task = asyncio.create_task(pdu_worker())
        pb_link.on_provisioning_pdu = lambda pdu: pdu_queue.put_nowait(pdu)
        
        # Start by sending INVITE
        await pb_link.send_transaction(session.invite())
        await worker_task

    async def start(self):
        await self.bearer.start()

    def _on_unprovisioned_device(self, uuid, rssi, oob_info):
        logger.info(f"Found Unprovisioned Device: UUID={uuid.hex()}")

    async def provision_device(self, uuid: bytes, auth_value: bytes = None):
        nodes = self.storage.get_nodes()
        next_addr = self.unicast_address + 1
        if nodes: next_addr = max(n['address'] for n in nodes) + 1
            
        link_id = random.getrandbits(32)
        pb_link = PBAdvLink(link_id, lambda pdu: self.bearer.send_pdu(pdu, is_pb_adv=True))
        self.provisioning_sessions[link_id] = pb_link
        await pb_link.open(uuid)
        
        session = ProvisioningSession()
        if auth_value: session.set_auth_value(auth_value)
        self.provisioning_states[link_id] = session
        
        pdu_queue = asyncio.Queue()

        async def pdu_worker():
            while True:
                pdu = await pdu_queue.get()
                try:
                    # Current session status
                    if session.state in (ProvisioningState.FAILED, ProvisioningState.COMPLETE):
                        break
                    
                    resp = session.handle_pdu(pdu, net_key=self.net_key, iv_index=self.iv_index, unicast_address=next_addr)
                    
                    if resp:
                        async def send_task(p_to_send):
                            if p_to_send[0] == 0x02: # START
                                success = await pb_link.send_transaction(p_to_send)
                                if success:
                                    # --- TRIGGER BROADCAST IMMEDIATELY AFTER START ---
                                    if session.auth_method != 0x00:
                                        session.state = ProvisioningState.AUTH_INPUT
                                        if self.on_auth_needed:
                                            asyncio.create_task(self.on_auth_needed(uuid, session.auth_method))
                                    
                                    # Silence window: Let BlueZ process our START
                                    await asyncio.sleep(1.0)
                                    logger.info("Sending Local Public Key (65 bytes)...")
                                    success = await pb_link.send_transaction(session.get_public_key_pdu())
                                    if success:
                                        logger.info("[CONFIRM] Local Public Key has been FULLY SENT and ACKED by device.")
                            else:
                                await pb_link.send_transaction(p_to_send)
                        
                        # Wait for Data TX to finish before checking final state
                        if pdu[0] == 0x06: # We just received Random, 'resp' is Data (Type 07)
                            await send_task(resp)
                        else:
                            asyncio.create_task(send_task(resp))

                    # Re-check state after handling PDU
                    if session.state == ProvisioningState.COMPLETE:
                        logger.info(f"Provisioning Successful! Node Address: {next_addr:04x}")
                        self.storage.save_node(next_addr, uuid, session.shared_secret)
                        self.upper_transport.add_dev_key(next_addr, session.shared_secret)
                        
                        # --- START AUTOMATIC CONFIGURATION ---
                        asyncio.create_task(self.config_manager.configure_node(next_addr, 0, b'\x02'*16))
                        break
                except Exception as e: logger.error(f"Worker Error: {e}")
                finally: pdu_queue.task_done()

        worker_task = asyncio.create_task(pdu_worker())
        pb_link.on_provisioning_pdu = lambda pdu: pdu_queue.put_nowait(pdu)
        asyncio.create_task(pb_link.send_transaction(session.invite()))
        await worker_task

    async def resume_provisioning_with_pin(self, uuid: bytes, pin: int):
        for link_id, session in self.provisioning_states.items():
            if session.state == ProvisioningState.AUTH_INPUT:
                # Security Gate: Ensure we have the peer's public key before proceeding
                wait_start = time.time()
                while session.shared_secret is None:
                    if time.time() - wait_start > 15.0:
                        logger.error("Timed out waiting for Public Key reassembly.")
                        return
                    await asyncio.sleep(0.5)
                
                logger.info("Keys ready. Sending Input Complete and Confirmation.")
                auth_val_hex = pin.to_bytes(16, 'big').hex()
                logger.info(f"[UI] Calculated AuthValue for PIN {pin}: {auth_val_hex}")
                session.set_auth_value(pin.to_bytes(16, 'big'))
                
                async def do_resume():
                    # 1. Send Input Complete (Required for Output OOB)
                    logger.info("TX: Provisioning Input Complete (0x04)")
                    await self.provisioning_sessions[link_id].send_transaction(b'\x04')
                    # 2. Send Provisioning Confirm
                    logger.info("TX: Provisioning Confirm (0x05)")
                    await self.provisioning_sessions[link_id].send_transaction(session._send_confirm())
                
                asyncio.create_task(do_resume())
                break

    def _on_bearer_pdu(self, pdu: bytes):
        if len(pdu) >= 6:
            link_id = int.from_bytes(pdu[0:4], 'big')
            if link_id in self.provisioning_sessions:
                self.provisioning_sessions[link_id].handle_pdu(pdu)
                return
        result = self.network.decrypt_pdu(pdu)
        if not result: return
        src, dst, seq, transport_pdu_raw = result
        res = self.transport.assemble_pdu(src, transport_pdu_raw, seq=seq)
        if not res: return
        full_pdu, akf_or_ctl, seq_auth, block = res
        
        # If it was a segmented message, we MUST send a Segment ACK
        if transport_pdu_raw[0] & 0x80:
            asyncio.create_task(self._send_control_message(src, self.transport.create_segment_ack(seq_auth & 0x1FFF, block)))
        
        if not full_pdu: return 
        
        # Decrypt based on AKF bit from the PDU
        # Config messages (akf_or_ctl=0) use DevKey, others use AppKey
        access_pdu = self.upper_transport.decrypt(src, dst, seq_auth, self.network.iv_index, full_pdu, akf=akf_or_ctl, aid=0)
        if access_pdu: self.access.handle_pdu(src, dst, 0, access_pdu)

    async def _send_control_message(self, dst: int, payload: bytes):
        # Control messages (CTL=1) have a different MIC length and Nonce
        segments = self.transport.segment_pdu(self.unicast_address, dst, self.network.seq, payload, ctl=1)
        for seg in segments:
            await self.bearer.send_pdu(self.network.encrypt_pdu(self.unicast_address, dst, seg, ctl=1), is_pb_adv=False)

    async def send_model_message(self, dst: int, model, opcode: int, payload: bytes, app_key: bytes = None):
        self.storage.set_setting("seq", self.network.seq + 1)
        access_pdu = self._create_access_pdu(opcode, payload)
        if model.MODEL_ID == 0x0001:
            key = self.upper_transport.get_dev_key(dst) or b'\x00'*16
            akf, aid = 0, 0
        else:
            key = app_key or b'\x00'*16
            akf, aid = 1 if app_key else 0, 0
        encrypted = self.upper_transport.encrypt(self.unicast_address, dst, self.network.seq, self.network.iv_index, access_pdu, key, akf, aid)
        segments = self.transport.segment_pdu(self.unicast_address, dst, self.network.seq, encrypted, akf, aid)
        for seg in segments:
            await self.bearer.send_pdu(self.network.encrypt_pdu(self.unicast_address, dst, seg), is_pb_adv=False)

    def _create_access_pdu(self, opcode: int, payload: bytes) -> bytes:
        if opcode < 0x80: return bytes([opcode]) + payload
        elif opcode < 0x10000: return opcode.to_bytes(2, 'big') + payload
        else: return opcode.to_bytes(3, 'big') + payload
