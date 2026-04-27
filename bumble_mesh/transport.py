import math
import logging
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)

class LowerTransportLayer:
    """
    Standard Mesh Segmentation and Reassembly (SAR).
    Strictly aligned with BlueZ 5.86 and Mesh Spec v1.1.
    """
    def __init__(self):
        self.rx_sessions: Dict[tuple, Dict] = {} # (src, seq_zero) -> session info

    def segment_pdu(self, src: int, dst: int, seq: int, pdu: bytes, akf: int = 0, aid: int = 0) -> List[bytes]:
        """Segments an Upper Transport PDU into Lower Transport PDUs."""
        
        # Access PDU MTUs:
        # Unsegmented: 1 header octet + 11 payload octets = 12 octets total
        # Segmented: 4 header octets + 12 payload octets per segment
        
        if len(pdu) <= 11:
            # Unsegmented Access PDU
            # Header: SEG(1=0) || AKF(1) || AID(6)
            h0 = ((akf & 1) << 6) | (aid & 0x3F)
            return [bytes([h0]) + pdu]
        
        # Segmented Access PDU
        segments = []
        seg_n = math.ceil(len(pdu) / 12) - 1
        seq_zero = seq & 0x1FFF
        
        for i in range(seg_n + 1):
            # Header (4 octets):
            # octet 0: SEG(1=1) || AKF(1) || AID(6)
            # octet 1: RFU(1=0) || SeqZero(high 7 bits)
            # octet 2: SeqZero(low 6 bits) || SegO(high 2 bits)
            # octet 3: SegO(low 3 bits) || SegN(5 bits)
            
            h0 = 0x80 | ((akf & 1) << 6) | (aid & 0x3F)
            h1 = (seq_zero >> 6) & 0x7F
            h2 = ((seq_zero & 0x3F) << 2) | ((i >> 3) & 0x03)
            h3 = ((i & 0x07) << 5) | (seg_n & 0x1F)
            
            header = bytes([h0, h1, h2, h3])
            payload = pdu[i*12 : (i+1)*12]
            segments.append(header + payload)
            
        return segments

    def assemble_pdu(self, src: int, pdu: bytes) -> Optional[bytes]:
        """Reassembles incoming segments from the network."""
        if len(pdu) < 1: return None
        
        is_segmented = (pdu[0] & 0x80) != 0
        
        if not is_segmented:
            # Unsegmented: Strip 1-byte header
            return pdu[1:]
        
        if len(pdu) < 4: return None
        
        # Segmented: Strip 4-byte header
        h0, h1, h2, h3 = pdu[0:4]
        seq_zero = ((h1 & 0x7F) << 6) | (h2 >> 2)
        seg_o = ((h2 & 0x03) << 3) | (h3 >> 5)
        seg_n = h3 & 0x1F
        
        key = (src, seq_zero)
        if key not in self.rx_sessions:
            self.rx_sessions[key] = {
                'total': seg_n + 1,
                'parts': {},
                'ts': 0 
            }
            
        session = self.rx_sessions[key]
        session['parts'][seg_o] = pdu[4:]
        
        if len(session['parts']) == session['total']:
            full_pdu = b''
            for i in range(session['total']):
                full_pdu += session['parts'][i]
            del self.rx_sessions[key]
            return full_pdu
            
        return None
