from ..access import Model
import logging

logger = logging.getLogger(__name__)

class GenericOnOffClient(Model):
    """
    Generic OnOff Client Model (Model ID: 0x1001)
    Used to control OnOff Servers (e.g. lights).
    """
    MODEL_ID = 0x1001
    
    def __init__(self):
        super().__init__(self.MODEL_ID)
        self.register_handler(0x8204, self._handle_onoff_status)
        self.on_onoff_status = None

    def _handle_onoff_status(self, src, payload):
        present_onoff = payload[0]
        target_onoff = payload[1] if len(payload) > 1 else None
        remaining_time = payload[2] if len(payload) > 2 else None
        
        status_str = "ON" if present_onoff else "OFF"
        logger.info(f"--- OnOff Status from {src:04x}: {status_str} ---")
        if self.on_onoff_status:
            self.on_onoff_status(src, present_onoff, target_onoff, remaining_time)

    # --- Command methods ---

    def get(self):
        """Opcode 0x8201: Generic OnOff Get"""
        return 0x8201, b''

    def set(self, onoff: bool, ack: bool = True, tid: int = 0):
        """
        Opcode 0x8202 (Set) or 0x8203 (Set Unacknowledged)
        onoff: True for ON, False for OFF
        """
        opcode = 0x8202 if ack else 0x8203
        payload = bytes([1 if onoff else 0, tid & 0xFF])
        return opcode, payload
