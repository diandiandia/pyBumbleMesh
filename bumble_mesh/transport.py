import math
import logging
from typing import List, Optional, Dict

logger = logging.getLogger(__name__)

class LowerTransportLayer:
    """
    Standard Mesh Segmentation and Reassembly (SAR).
    """
    def __init__(self):
        self.rx_sessions: Dict[tuple, Dict] = {} # (src, seq_zero) -> session info

    def segment_pdu(self, src: int, dst: int, seq: int, pdu: bytes) -> List[bytes]:
        """Segments an Upper Transport PDU."""
        if len(pdu) <= 15: # Unsegmented (1 byte header + 15 bytes data)
            return [bytes([0x00]) + pdu] # SEG=0
        
        # Segmented
        segments = []
        seg_n = math.ceil(len(pdu) / 12) - 1
        seq_zero = seq & 0x1FFF
        
        for i in range(seg_n + 1):
            # Header: SEG(1) || AKF(0) || AID(0) || RFU(1) || SeqZero(13) || SegO(5) || SegN(5)
            # Simplified: assuming AKF=0, AID=0
            h0 = 0x80 | ((seq_zero >> 6) & 0x3F)
            h1 = ((seq_zero & 0x3F) << 2) | ((i >> 3) & 0x03)
            h2 = ((i & 0x07) << 5) | (seg_n & 0x1F)
            
            header = bytes([h0, h1, h2])
            payload = pdu[i*12 : (i+1)*12]
            segments.append(header + payload)
            
        return segments

    def assemble_pdu(self, src: int, pdu: bytes) -> Optional[bytes]:
        """Reassembles incoming segments."""
        if (pdu[0] & 0x80) == 0:
            # Unsegmented
            return pdu[1:]
        
        # Segmented
        h0, h1, h2 = pdu[0:3]
        seq_zero = ((h0 & 0x3F) << 6) | (h1 >> 2)
        seg_o = ((h1 & 0x03) << 3) | (h2 >> 5)
        seg_n = h2 & 0x1F
        
        key = (src, seq_zero)
        if key not in self.rx_sessions:
            self.rx_sessions[key] = {
                'total': seg_n + 1,
                'parts': {},
                'ts': 0 # Could add timeout
            }
            
        session = self.rx_sessions[key]
        session['parts'][seg_o] = pdu[3:]
        
        if len(session['parts']) == session['total']:
            full_pdu = b''
            for i in range(session['total']):
                full_pdu += session['parts'][i]
            del self.rx_sessions[key]
            return full_pdu
            
        return None
