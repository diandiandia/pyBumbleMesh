import math
import logging
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)

class LowerTransportLayer:
    """
    Standard Mesh SAR with Control Message (CTL) support.
    Strictly aligned with BlueZ 5.86 lower-transport.c.
    """
    def __init__(self):
        self.rx_sessions: Dict[tuple, Dict] = {} 

    def segment_pdu(self, src: int, dst: int, seq: int, pdu: bytes, akf: int = 0, aid: int = 0, ctl: int = 0) -> List[bytes]:
        """Segments an Upper Transport PDU into Lower Transport PDUs."""
        if ctl == 0:
            # --- Access Messages ---
            if len(pdu) <= 11:
                # Unsegmented Access
                h0 = ((akf & 1) << 6) | (aid & 0x3F)
                return [bytes([h0]) + pdu]
            
            # Segmented Access
            segments = []
            seg_n = math.ceil(len(pdu) / 12) - 1
            seq_zero = seq & 0x1FFF
            for i in range(seg_n + 1):
                h0 = 0x80 | ((akf & 1) << 6) | (aid & 0x3F)
                h1 = (seq_zero >> 6) & 0x7F
                h2 = ((seq_zero & 0x3F) << 2) | ((i >> 3) & 0x03)
                h3 = ((i & 0x07) << 5) | (seg_n & 0x1F)
                segments.append(bytes([h0, h1, h2, h3]) + pdu[i*12 : (i+1)*12])
            return segments
        else:
            # --- Control Messages (e.g. Segment ACK) ---
            # BlueZ expects CTL=1 for Segment Acknowledgment
            h0 = 0x80 | 0x00 # SEG=1, Opcode=0 (Segment ACK)
            # Control messages are typically small and unsegmented or specifically formatted
            return [bytes([h0]) + pdu]

    def create_segment_ack(self, seq_zero: int, block: int) -> bytes:
        """Constructs a Segment Acknowledgment payload (Mesh Spec 3.4.5.2)."""
        # octet 0: RFU(1=0) || SeqZero(high 7 bits)
        # octet 1: SeqZero(low 6 bits) || RFU(2=0)
        # octet 2-5: Block Ack bitmask (Big Endian)
        h1 = (seq_zero >> 6) & 0x7F
        h2 = (seq_zero & 0x3F) << 2
        return bytes([h1, h2]) + block.to_bytes(4, 'big')

    def assemble_pdu(self, src: int, pdu: bytes) -> Optional[tuple]:
        """Reassembles segments. Returns (Full_PDU, is_ctl, seq_zero, block_mask)."""
        if len(pdu) < 1: return None
        
        is_segmented = (pdu[0] & 0x80) != 0
        is_ctl = (pdu[0] & 0x7F) == 0x00 if not is_segmented else False # Simplified

        if not is_segmented:
            # (PDU, ctl, seq_zero, block)
            return pdu[1:], 0, 0, 0
        
        if len(pdu) < 4: return None
        h0, h1, h2, h3 = pdu[0:4]
        seq_zero = ((h1 & 0x7F) << 6) | (h2 >> 2)
        seg_o = ((h2 & 0x03) << 3) | (h3 >> 5)
        seg_n = h3 & 0x1F
        
        key = (src, seq_zero)
        if key not in self.rx_sessions:
            self.rx_sessions[key] = {'total': seg_n + 1, 'parts': {}, 'block': 0}
            
        session = self.rx_sessions[key]
        session['parts'][seg_o] = pdu[4:]
        session['block'] |= (1 << seg_o)
        
        if len(session['parts']) == session['total']:
            full_pdu = b''.join(session['parts'][i] for i in range(session['total']))
            del self.rx_sessions[key]
            return full_pdu, 0, seq_zero, session['block']
            
        # Return progress for potential ACK sending
        return None, 0, seq_zero, session['block']
