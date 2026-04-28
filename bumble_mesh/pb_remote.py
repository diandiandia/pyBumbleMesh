import asyncio
import logging
from typing import Optional, Callable

logger = logging.getLogger(__name__)

class PBRemoteLink:
    """
    PB-Remote Link Layer (Mesh v1.1).
    Encapsulates Provisioning PDUs into Remote Provisioning Client messages.
    """
    def __init__(self, stack, server_addr: int, rp_client, app_key: bytes = None):
        self.stack = stack
        self.server_addr = server_addr
        self.rp_client = rp_client
        self.app_key = app_key
        self.outbound_pdu_count = 1
        self.on_provisioning_pdu: Optional[Callable[[bytes], None]] = None
        
        self.link_ack_received = asyncio.Event()
        self.pdu_ack_received = asyncio.Event() # For reliability if needed

        # Hook into RP Client reports
        self.rp_client.on_pdu_report = self._on_pdu_report
        self.rp_client.on_link_status = self._on_link_status
        self.rp_client.on_pdu_outbound_report = self._on_pdu_outbound_report

    def _on_pdu_report(self, src, pdu):
        if src == self.server_addr and self.on_provisioning_pdu:
            self.on_provisioning_pdu(pdu)

    def _on_pdu_outbound_report(self, src, count):
        if src == self.server_addr:
            self.pdu_ack_received.set()

    def _on_link_status(self, src, status, link_state):
        if src == self.server_addr and status == 0 and link_state in (1, 2):
            self.link_ack_received.set()

    async def open(self, device_uuid: bytes, timeout: float = 20.0):
        logger.info(f"Opening PB-Remote link via {self.server_addr:04x}...")
        self.link_ack_received.clear()
        
        opcode, payload = self.rp_client.link_open(device_uuid)
        await self.stack.send_model_message(self.server_addr, self.rp_client, opcode, payload, app_key=self.app_key)
        
        try:
            await asyncio.wait_for(self.link_ack_received.wait(), timeout)
            logger.info("PB-Remote Link Opened.")
            return True
        except asyncio.TimeoutError:
            logger.error("PB-Remote Link Open Timeout")
            return False

    async def send_transaction(self, pdu: bytes, timeout: float = 10.0) -> bool:
        """Sends a provisioning PDU via the remote node reliably."""
        logger.info(f"TX Remote Trans: Type {pdu[0]:02x}, Count {self.outbound_pdu_count}")
        self.pdu_ack_received.clear()
        
        opcode, payload = self.rp_client.pdu_send(self.outbound_pdu_count, pdu)
        await self.stack.send_model_message(self.server_addr, self.rp_client, opcode, payload, app_key=self.app_key)
        
        try:
            await asyncio.wait_for(self.pdu_ack_received.wait(), timeout)
            self.outbound_pdu_count = (self.outbound_pdu_count + 1) % 256
            return True
        except asyncio.TimeoutError:
            logger.error(f"Remote PDU ACK Timeout (Count {self.outbound_pdu_count})")
            return False

    async def close(self, reason: int = 0x00):
        opcode, payload = self.rp_client.link_close(reason)
        await self.stack.send_model_message(self.server_addr, self.rp_client, opcode, payload)
        logger.info("PB-Remote Link Closed.")
