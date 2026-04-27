import logging
import asyncio
import random
from .bearer import AdvBearer
from .network import NetworkLayer
from .transport import LowerTransportLayer
from .access import AccessLayer
from .pb_adv import PBAdvLink
from .provisioning import ProvisioningSession, ProvisioningState
from .upper_transport import UpperTransportLayer
from .storage import MeshStorage

logger = logging.getLogger(__name__)

class MeshStack:
    def __init__(self, device, net_key: bytes, unicast_address: int, db_path: str = "mesh_database.db"):
        self.storage = MeshStorage(db_path)
        
        # Load or use provided settings
        self.unicast_address = int(self.storage.get_setting("unicast_address", unicast_address))
        self.storage.set_setting("unicast_address", self.unicast_address)
        
        # Load NetKey
        networks = self.storage.get_networks()
        if not networks:
            self.storage.save_network(0, net_key, 0)
            self.net_key = net_key
            self.iv_index = 0
        else:
            self.net_key = networks[0]['key']
            self.iv_index = networks[0]['iv_index']

        # Load Sequence Number
        self.network = NetworkLayer(self.net_key, iv_index=self.iv_index)
        self.network.seq = int(self.storage.get_setting("seq", 0))
        
        self.bearer = AdvBearer(device)
        self.upper_transport = UpperTransportLayer()
        
        # Load DevKeys for existing nodes
        for node in self.storage.get_nodes():
            self.upper_transport.add_dev_key(node['address'], node['dev_key'])
            
        self.transport = LowerTransportLayer()
        self.access = AccessLayer()
        self.provisioning_sessions = {} # UUID -> PBAdvLink
        self.provisioning_states = {} # UUID -> ProvisioningSession
        
        # Link events
        self.bearer.on_pdu = self._on_bearer_pdu
        self.bearer.on_unprovisioned_device = self._on_unprovisioned_device

    async def start(self):
        await self.bearer.start()

    def _on_unprovisioned_device(self, uuid, rssi, oob_info):
        logger.info(f"Found Unprovisioned Device: UUID={uuid.hex()}, RSSI={rssi}, OOB={oob_info.hex()}")

    async def provision_device(self, uuid: bytes, auth_value: bytes = None):
        """Starts a full PB-ADV provisioning process for a device."""
        nodes = self.storage.get_nodes()
        next_addr = self.unicast_address + 1
        if nodes: next_addr = max(n['address'] for n in nodes) + 1
            
        link_id = random.getrandbits(32)
        pb_link = PBAdvLink(link_id, lambda pdu: asyncio.create_task(self.bearer.send_pdu(pdu, is_pb_adv=True)))
        self.provisioning_sessions[link_id] = pb_link
        
        await pb_link.open(uuid)
        
        session = ProvisioningSession()
        if auth_value:
            session.set_auth_value(auth_value)
        self.provisioning_states[link_id] = session
        
        def on_pdu(pdu):
            async def handle():
                resp = session.handle_pdu(pdu, net_key=self.net_key, iv_index=self.iv_index, unicast_address=next_addr)
                if resp:
                    await pb_link.send_transaction(resp)
                    
                    # If we just sent PROV_START, we must immediately follow with PUBLIC_KEY
                    if resp[0] == 0x02:
                        pub_key_pdu = session.get_public_key_pdu()
                        await pb_link.send_transaction(pub_key_pdu)
                
                # Special Check: If session enters AUTH_INPUT, it won't return a response yet.
                # The interactive script will detect this state and call set_auth_value.
                # Once set_auth_value is called, we must manually trigger the next step (Confirm).
                
                if session.state == ProvisioningState.COMPLETE:
                    logger.info(f"Provisioning Successful! Node Address: {next_addr:04x}")
                    self.storage.save_node(next_addr, uuid, session.shared_secret)
                    self.upper_transport.add_dev_key(next_addr, session.shared_secret)
            asyncio.create_task(handle())
        
        pb_link.on_provisioning_pdu = on_pdu

    async def resume_provisioning_with_pin(self, uuid: bytes, pin: int):
        """Resumes a provisioning session after the user provides a numeric PIN."""
        # Find the session
        # This is a bit tricky as sessions are stored by link_id in provisioning_sessions
        # and provisioning_states.
        for link_id, session in self.provisioning_states.items():
            # For simplicity, we assume one active session or match by some logic
            if session.state == ProvisioningState.AUTH_INPUT:
                # 1. Convert PIN to 16-octet big-endian AuthValue
                auth_value = pin.to_bytes(16, 'big')
                session.set_auth_value(auth_value)
                
                # 2. Manually trigger the next step (Confirm)
                confirm_pdu = session._send_confirm()
                pb_link = self.provisioning_sessions[link_id]
                await pb_link.send_transaction(confirm_pdu)
                break
        
        # Start the flow
        invite_pdu = session.invite()
        await pb_link.send_transaction(invite_pdu)

    async def remote_provision_device(self, server_addr: int, device_uuid: bytes):
        """
        Starts a Remote Provisioning process through a relay server.
        """
        # 1. Find the Remote Provisioning Client model
        rp_client = next((m for m in self.access.models.values() if isinstance(m, RemoteProvisioningClient)), None)
        if not rp_client:
            logger.error("Remote Provisioning Client model not registered.")
            return

        # 2. Setup next available address
        nodes = self.storage.get_nodes()
        next_addr = self.unicast_address + 1
        if nodes: next_addr = max(n['address'] for n in nodes) + 1

        # 3. Create a standard provisioning session
        session = ProvisioningSession()
        outbound_count = 0
        
        # 4. Define callback for inbound tunnel PDUs
        def on_inbound_pdu(src, pdu):
            if src != server_addr: return
            
            async def handle():
                nonlocal outbound_count
                resp = session.handle_pdu(pdu, net_key=self.net_key, iv_index=self.iv_index, unicast_address=next_addr)
                if resp:
                    outbound_count = (outbound_count + 1) & 0xFF
                    opcode, payload = rp_client.pdu_send(outbound_count, resp)
                    await self.send_model_message(server_addr, rp_client, opcode, payload)
                    
                    if resp[0] == 0x02: # If START, follow with PUBKEY
                        outbound_count = (outbound_count + 1) & 0xFF
                        opcode, payload = rp_client.pdu_send(outbound_count, session.get_public_key_pdu())
                        await self.send_model_message(server_addr, rp_client, opcode, payload)

                if session.state == ProvisioningState.COMPLETE:
                    logger.info(f"REMOTE Provisioning Successful! Node: {next_addr:04x}")
                    self.storage.save_node(next_addr, device_uuid, session.shared_secret)
                    self.upper_transport.add_dev_key(next_addr, session.shared_secret)
            
            asyncio.create_task(handle())

        rp_client.on_pdu_report = on_inbound_pdu

        # 5. Open Remote Link
        logger.info(f"Opening Remote Provisioning Link via 0x{server_addr:04x}...")
        opcode, payload = rp_client.link_open(device_uuid)
        await self.send_model_message(server_addr, rp_client, opcode, payload)
        
        # Wait for Link Status (Simplified)
        await asyncio.sleep(2)
        
        # 6. Start Handshake by sending Invite
        logger.info("Sending Remote Invite...")
        invite_pdu = session.invite()
        outbound_count = (outbound_count + 1) & 0xFF
        opcode, payload = rp_client.pdu_send(outbound_count, invite_pdu)
        await self.send_model_message(server_addr, rp_client, opcode, payload)

    def _on_bearer_pdu(self, pdu: bytes):
        # Check if it's potentially PB-ADV (handled by bearer already based on AD Type)
        # But we need to know if the bearer passed it to us.
        # Currently bearer calls on_pdu for both Mesh PDU and PB-ADV.
        # We need to distinguish them.
        
        # If length is small and looks like PB-ADV (Link ID at start)
        if len(pdu) >= 6:
            link_id = int.from_bytes(pdu[0:4], 'big')
            if link_id in self.provisioning_sessions:
                self.provisioning_sessions[link_id].handle_pdu(pdu)
                return

        # Fallback to Mesh PDU Decryption
        result = self.network.decrypt_pdu(pdu)
        if not result:
            return
            
        src, dst, transport_pdu_raw = result
        
        # 2. Transport Reassemble
        transport_pdu = self.transport.assemble_pdu(src, transport_pdu_raw)
        if not transport_pdu:
            return
            
        # 3. Upper Transport Decrypt
        access_pdu = self.upper_transport.decrypt(
            src, dst, self.network.seq, self.network.iv_index, transport_pdu, akf=0, aid=0
        )
        if not access_pdu:
            return
            
        # 4. Access Handle
        self.access.handle_pdu(src, dst, 0, access_pdu)

    async def send_model_message(self, dst: int, model, opcode: int, payload: bytes, app_key: bytes = None):
        """
        Sends an encrypted message from a model to a destination.
        """
        # Save SEQ to database before sending (to avoid reuse on crash)
        self.storage.set_setting("seq", self.network.seq + 1)
        
        # 1. Create Access PDU
        access_pdu = self._create_access_pdu(opcode, payload)
        
        # 2. Upper Transport Layer (Encryption)
        # Use a default DevKey if no AppKey is provided (simplified)
        key = app_key if app_key else b'\x00' * 16 # Placeholder
        encrypted_pdu = self.upper_transport.encrypt(
            self.unicast_address, dst, self.network.seq, self.network.iv_index,
            access_pdu, key, akf=0, aid=0
        )
        
        # 3. Lower Transport Layer (Segmentation)
        segments = self.transport.segment_pdu(self.unicast_address, dst, self.network.seq, encrypted_pdu)
        
        # 4. Network Layer (Encryption) & Bearer Layer (Send)
        for segment in segments:
            network_pdu = self.network.encrypt_pdu(self.unicast_address, dst, segment)
            await self.bearer.send_pdu(network_pdu, is_pb_adv=False)

    def _create_access_pdu(self, opcode: int, payload: bytes) -> bytes:
        if opcode < 0x80:
            return bytes([opcode]) + payload
        elif opcode < 0x10000:
            return opcode.to_bytes(2, 'big') + payload
        else:
            return opcode.to_bytes(3, 'big') + payload
