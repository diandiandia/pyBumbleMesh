import asyncio
import logging
import random
from typing import Dict, List
from .models.config import ConfigClient

logger = logging.getLogger(__name__)

class MeshConfigManager:
    """
    Automates the standard Mesh Configuration Flow.
    1. Composition Data Get
    2. AppKey Add
    3. Model App Bind
    """
    def __init__(self, stack):
        self.stack = stack
        self.config_client = ConfigClient()
        self.stack.access.register_model(self.config_client)
        
        self.pending_responses = {} # {msg_type: Event}

    async def configure_node(self, node_addr: int, app_key_index: int, app_key: bytes):
        logger.info(f"--- Starting Standard Configuration for Node {node_addr:04x} ---")
        
        # Ensure AppKey is known locally
        self.stack.upper_transport.add_app_key(app_key_index, app_key)
        self.stack.storage.save_app_key(app_key_index, app_key)

        # 1. Composition Data Get (With Retry)
        logger.info("[1/3] Fetching Composition Data...")
        comp_event = asyncio.Event()
        comp_data = None
        
        def on_comp(src, page, data):
            nonlocal comp_data
            if src == node_addr:
                comp_data = data
                comp_event.set()
        
        self.config_client.on_composition_data = on_comp
        opcode, payload = self.config_client.composition_data_get()

        for attempt in range(1, 4):
            logger.info(f"  Attempt {attempt}/3: Sending Composition Data Get...")
            comp_event.clear()
            await self.stack.send_model_message(node_addr, self.config_client, opcode, payload)
            try:
                await asyncio.wait_for(comp_event.wait(), timeout=5.0)
                self._save_composition(node_addr, comp_data)
                break
            except asyncio.TimeoutError:
                if attempt == 3:
                    logger.error("Final Timeout waiting for Composition Data Status")
                    return False
                logger.warning(f"  Attempt {attempt} timed out. Retrying...")

        # 2. AppKey Add (with retry)
        logger.info("[2/3] Adding AppKey...")
        ack_event = asyncio.Event()
        
        def on_ack_status(src, status, index):
            if src == node_addr and index == app_key_index:
                if status == 0: logger.info("AppKey Added Successfully")
                else: logger.error(f"AppKey Add Failed with status {status}")
                ack_event.set()
        
        self.config_client.on_appkey_status = on_ack_status
        opcode, payload = self.config_client.appkey_add(0, app_key_index, app_key)
        
        for attempt in range(1, 6):
            # Add random jitter to avoid colliding with device beacon window
            jitter = random.uniform(0.5, 2.0)
            logger.info(f"  AppKey Add Attempt {attempt}/5 (jitter {jitter:.1f}s)...")
            await asyncio.sleep(jitter)
            ack_event.clear()
            await self.stack.send_model_message(node_addr, self.config_client, opcode, payload)
            try:
                await asyncio.wait_for(ack_event.wait(), timeout=5.0)
                break
            except asyncio.TimeoutError:
                if attempt == 3:
                    logger.warning("AppKey Add final timeout (continuing anyway)")
                else:
                    logger.warning(f"  AppKey Add Attempt {attempt} timed out. Retrying...")

        # 3. Send AppKey to ourselves (gateway) so that bluetooth-meshd knows it too
        logger.info("[2.5/3] Sending AppKey to gateway (0x%04x)...", self.stack.unicast_address)
        ack_event = asyncio.Event()

        def on_gw_ack_status(src, status, index):
            if src == self.stack.unicast_address and index == app_key_index:
                if status == 0:
                    logger.info("Gateway AppKey Added Successfully")
                else:
                    logger.error(f"Gateway AppKey Add Failed with status {status}")
                ack_event.set()

        self.config_client.on_appkey_status = on_gw_ack_status
        opcode, payload = self.config_client.appkey_add(0, app_key_index, app_key)

        for attempt in range(1, 6):
            jitter = random.uniform(0.5, 2.0)
            logger.info(f"  Gateway AppKey Add Attempt {attempt}/5 (jitter {jitter:.1f}s)...")
            await asyncio.sleep(jitter)
            ack_event.clear()
            await self.stack.send_model_message(self.stack.unicast_address, self.config_client, opcode, payload)
            try:
                await asyncio.wait_for(ack_event.wait(), timeout=5.0)
                break
            except asyncio.TimeoutError:
                if attempt == 3:
                    logger.warning("Gateway AppKey Add final timeout (continuing anyway)")
                else:
                    logger.warning(f"  Gateway AppKey Add Attempt {attempt} timed out. Retrying...")

        # 4. Model App Bind (Bind all discovered SIG models)
        logger.info("[3/3] Binding discovered SIG models to AppKey...")
        models = self.stack.storage.get_node_models(node_addr)
        for m in models:
            if m['model_id'] in (0x0000, 0x0001, 0x0002, 0x0003): continue # Skip foundation models
            
            logger.info(f"Binding Model {m['model_id']:04x} on Element {m['elem_addr']:04x}...")
            opcode, payload = self.config_client.model_app_bind(m['elem_addr'], app_key_index, m['model_id'])
            await self.stack.send_model_message(node_addr, self.config_client, opcode, payload)
            await asyncio.sleep(0.5) # Gap between binds

        logger.info(f"--- Configuration for {node_addr:04x} COMPLETE ---")
        return True

    def _save_composition(self, node_addr, data):
        # Extract models and save to DB
        offset = 10
        elem_idx = 0
        while offset < len(data):
            # Element Address = node_addr + elem_idx
            elem_addr = node_addr + elem_idx
            num_s = data[offset+2]
            num_v = data[offset+3]
            offset += 4
            
            for _ in range(num_s):
                mid = int.from_bytes(data[offset:offset+2], 'little')
                self.stack.storage.save_node_model(node_addr, elem_addr, mid, is_vendor=False)
                offset += 2
            for _ in range(num_v):
                mid = int.from_bytes(data[offset:offset+4], 'little')
                self.stack.storage.save_node_model(node_addr, elem_addr, mid, is_vendor=True)
                offset += 4
            elem_idx += 1
