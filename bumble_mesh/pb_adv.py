import asyncio
import logging
import math
import time
from typing import Optional, Callable, Dict, List
from .crypto import crc8

logger = logging.getLogger(__name__)

class PBAdvLink:
    """
    PB-ADV Link Layer (Source-Aligned with BlueZ 5.86).
    """
    RETRANSMIT_INTERVAL = 1.0 
    TRANSACTION_TIMEOUT = 30.0

    def __init__(self, link_id: int, send_pdu_cb: Callable[[bytes], None]):
        self.link_id = link_id
        self.send_pdu_cb = send_pdu_cb
        self.local_trans_num = 0x00
        self.on_provisioning_pdu: Optional[Callable[[bytes], None]] = None
        self.is_opened = False
        self.link_ack_received = asyncio.Event()
        self.trans_ack_received = asyncio.Event()
        self.current_ack_id: Optional[int] = None
        self.rx_buffer: Dict[int, Dict[int, bytes]] = {} 
        self.rx_info: Dict[int, Dict] = {} 
        self.tx_lock = asyncio.Lock()

    async def open(self, device_uuid: bytes, timeout: float = 10.0):
        # Open Req: [ID(4)] [Num(00)] [Opcode(03)] [UUID(16)] = 22 bytes
        pdu = self.link_id.to_bytes(4, 'big') + b'\x00\x03' + device_uuid
        self.link_ack_received.clear()
        start_time = time.time()
        while not self.link_ack_received.is_set():
            if time.time() - start_time > timeout: raise asyncio.TimeoutError("Link Open Timeout")
            self.send_pdu_cb(pdu)
            try: await asyncio.wait_for(self.link_ack_received.wait(), self.RETRANSMIT_INTERVAL)
            except asyncio.TimeoutError: continue
        self.is_opened = True
        self.local_trans_num = 0x00
        logger.info("PB-ADV Link Opened.")

    def handle_pdu(self, pdu: bytes):
        if len(pdu) < 5: return
        link_id = int.from_bytes(pdu[0:4], 'big')
        if link_id != self.link_id: return
        
        # In PB-ADV, index 5 is always Opcode/GPC
        gpc_byte = pdu[5]
        if (gpc_byte & 0x03) == 0x03:
            if gpc_byte == 0x07: self.link_ack_received.set()
            elif gpc_byte == 0x0B: self.is_opened = False
            return

        trans_num = pdu[4]
        if (gpc_byte & 0x03) == 0x01: # ACK
            if trans_num == self.current_ack_id: self.trans_ack_received.set()
        elif (gpc_byte & 0x03) == 0x00: # START
            total_len = int.from_bytes(pdu[6:8], 'big')
            fcs = pdu[8]
            self.rx_buffer[trans_num] = {0: pdu[9:]}
            self.rx_info[trans_num] = {'total_len': total_len, 'seg_n': gpc_byte >> 2, 'fcs': fcs}
            self._check_and_reassemble(trans_num)
            self._send_trans_ack(trans_num)
        elif (gpc_byte & 0x03) == 0x02: # CONT
            if trans_num in self.rx_buffer:
                self.rx_buffer[trans_num][gpc_byte >> 2] = pdu[6:]
                self._check_and_reassemble(trans_num)

    def _check_and_reassemble(self, trans_id: int):
        info = self.rx_info[trans_id]
        buffer = self.rx_buffer[trans_id]
        if len(buffer) == info['seg_n'] + 1:
            full_pdu = b''.join(buffer[i] for i in range(info['seg_n'] + 1))[:info['total_len']]
            if crc8(full_pdu) == info['fcs']:
                if self.on_provisioning_pdu: self.on_provisioning_pdu(full_pdu)
            del self.rx_buffer[trans_id]
            del self.rx_info[trans_id]

    async def send_transaction(self, pdu: bytes):
        async with self.tx_lock:
            self.local_trans_num = (self.local_trans_num + 1) % 256
            fcs = crc8(pdu)
            size = len(pdu)
            
            # --- BLUEZ 5.86 EXACT ALIGNMENT ---
            # Start: [ID(4)] [Num(1)] [GPC(1)] [Size(2)] [FCS(1)] [Payload]
            # Max Start Payload = 24 (BlueZ MTU) - 9 (Header) = 15 octets.
            # Max Cont Payload = 24 (BlueZ MTU) - 6 (Header) = 18 octets.
            first_seg_len = 15
            cont_seg_len = 18
            
            max_seg = math.ceil((size - first_seg_len) / cont_seg_len) if size > first_seg_len else 0
            
            segments = []
            # 1. Start
            header = self.link_id.to_bytes(4, 'big') + bytes([self.local_trans_num, (max_seg << 2)]) + \
                     size.to_bytes(2, 'big') + bytes([fcs])
            segments.append(header + pdu[:first_seg_len])
            
            # 2. Cont
            for i in range(1, max_seg + 1):
                header = self.link_id.to_bytes(4, 'big') + bytes([self.local_trans_num, (i << 2) | 0x02])
                start = first_seg_len + (i-1) * cont_seg_len
                segments.append(header + pdu[start : start + cont_seg_len])

            self.current_ack_id = self.local_trans_num
            self.trans_ack_received.clear()
            start_time = time.time()
            logger.info(f"TX Trans {self.local_trans_num} (Size: {size}, FCS: {fcs:02x}, Segs: {len(segments)})")
            
            while not self.trans_ack_received.is_set():
                if time.time() - start_time > self.TRANSACTION_TIMEOUT: break
                for seg in segments: self.send_pdu_cb(seg)
                try: await asyncio.wait_for(self.trans_ack_received.wait(), self.RETRANSMIT_INTERVAL)
                except asyncio.TimeoutError: continue

    def _send_trans_ack(self, trans_id: int):
        pdu = self.link_id.to_bytes(4, 'big') + bytes([trans_id, 0x01])
        self.send_pdu_cb(pdu)
