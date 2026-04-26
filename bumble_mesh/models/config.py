from ..access import Model
import logging

logger = logging.getLogger(__name__)

class ConfigClient(Model):
    """
    Configuration Client Model (Model ID: 0x0001)
    Used to configure nodes after provisioning.
    """
    MODEL_ID = 0x0001
    
    def __init__(self):
        super().__init__(self.MODEL_ID)
        # Register handlers
        self.register_handler(0x8003, self._handle_appkey_status)
        self.register_handler(0x803E, self._handle_model_app_status)
        self.register_handler(0x02, self._handle_composition_data_status)
        
        self.on_appkey_status = None
        self.on_model_app_status = None
        self.on_composition_data = None

    def _handle_appkey_status(self, src, payload):
        status = payload[0]
        net_key_index = int.from_bytes(payload[1:3], 'little') & 0xFFF
        app_key_index = int.from_bytes(payload[2:4], 'little') >> 4
        logger.info(f"AppKey Status from {src:04x}: Status={status}, AppKeyIndex={app_key_index}")
        if self.on_appkey_status:
            self.on_appkey_status(src, status, app_key_index)

    def _handle_model_app_status(self, src, payload):
        status = payload[0]
        element_addr = int.from_bytes(payload[1:3], 'little')
        app_key_index = int.from_bytes(payload[3:5], 'little')
        model_id = int.from_bytes(payload[5:], 'little')
        logger.info(f"Model App Status from {src:04x}: Status={status}, Model={model_id:04x}")
        if self.on_model_app_status:
            self.on_model_app_status(src, status, element_addr, app_key_index, model_id)

    def _handle_composition_data_status(self, src, payload):
        page = payload[0]
        data = payload[1:]
        logger.info(f"Composition Data (Page {page}) from {src:04x}: {data.hex()}")
        if self.on_composition_data:
            self.on_composition_data(src, page, data)

    # --- Command methods ---

    def composition_data_get(self, page: int = 0):
        # Opcode 0x8008
        return 0x8008, bytes([page])

    def appkey_add(self, net_key_index: int, app_key_index: int, app_key: bytes):
        # Opcode 0x00
        indices = (net_key_index & 0xFFF) | ((app_key_index & 0xFFF) << 12)
        payload = indices.to_bytes(3, 'little') + app_key
        return 0x00, payload

    def model_app_bind(self, element_addr: int, app_key_index: int, model_id: int):
        # Opcode 0x803D
        payload = element_addr.to_bytes(2, 'little') + \
                  app_key_index.to_bytes(2, 'little') + \
                  model_id.to_bytes(2, 'little')
        return 0x803D, payload
