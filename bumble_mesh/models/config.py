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
        self.register_handler(0x800B, self._handle_beacon_status)
        self.register_handler(0x800D, self._handle_ttl_status)
        self.register_handler(0x8027, self._handle_relay_status)
        self.register_handler(0x8013, self._handle_proxy_status)
        self.register_handler(0x8011, self._handle_friend_status)
        self.register_handler(0x8019, self._handle_pub_status)
        
        self.on_appkey_status = None
        self.on_model_app_status = None
        self.on_composition_data = None
        self.on_pub_status = None

    def _handle_beacon_status(self, src, payload):
        logger.info(f"Beacon Status from {src:04x}: {'Enabled' if payload[0] else 'Disabled'}")

    def _handle_ttl_status(self, src, payload):
        logger.info(f"Default TTL from {src:04x}: {payload[0]}")

    def _handle_relay_status(self, src, payload):
        logger.info(f"Relay Status from {src:04x}: {payload[0]}, Count: {payload[1] & 0x07}")

    def _handle_proxy_status(self, src, payload):
        logger.info(f"GATT Proxy Status from {src:04x}: {payload[0]}")

    def _handle_friend_status(self, src, payload):
        logger.info(f"Friend Status from {src:04x}: {payload[0]}")

    def _handle_pub_status(self, src, payload):
        status = payload[0]
        logger.info(f"Model Publication Status from {src:04x}: Status={status}")
        if self.on_pub_status: self.on_pub_status(src, status)

    # --- Additional Command methods ---

    def beacon_get(self): return 0x8009, b''
    def beacon_set(self, enable: bool): return 0x800A, bytes([1 if enable else 0])
    
    def ttl_get(self): return 0x800C, b''
    def ttl_set(self, ttl: int): return 0x800E, bytes([ttl])
    
    def relay_get(self): return 0x8026, b''
    def relay_set(self, relay: int, count: int, steps: int):
        # relay: 0=Off, 1=On, 2=Not supported
        return 0x8027, bytes([relay, (count & 0x07) | (steps << 3)])
    
    def proxy_get(self): return 0x8012, b''
    def proxy_set(self, proxy: int): return 0x8013, bytes([proxy])
    
    def friend_get(self): return 0x8010, b''
    def friend_set(self, friend: int): return 0x8011, bytes([friend])

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
        logger.info(f"--- Composition Data Page {page} from {src:04x} ---")
        
        # Simple parser for Page 0
        if page == 0:
            cid = int.from_bytes(data[0:2], 'little')
            pid = int.from_bytes(data[2:4], 'little')
            vid = int.from_bytes(data[4:6], 'little')
            crpl = int.from_bytes(data[6:8], 'little')
            features = int.from_bytes(data[8:10], 'little')
            logger.info(f"Company ID: {cid:04x}, Product ID: {pid:04x}, Version: {vid:04x}")
            
            # Elements
            offset = 10
            elem_idx = 0
            while offset < len(data):
                loc = int.from_bytes(data[offset:offset+2], 'little')
                num_s = data[offset+2]
                num_v = data[offset+3]
                offset += 4
                logger.info(f"Element {elem_idx} (Loc: {loc:04x}): {num_s} SIG Models, {num_v} Vendor Models")
                
                # SIG Models
                for _ in range(num_s):
                    mid = int.from_bytes(data[offset:offset+2], 'little')
                    logger.info(f"  - SIG Model: {mid:04x}")
                    offset += 2
                # Vendor Models
                for _ in range(num_v):
                    mid = int.from_bytes(data[offset:offset+4], 'little')
                    logger.info(f"  - Vendor Model: {mid:08x}")
                    offset += 4
                elem_idx += 1
        
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

    def model_publication_set(self, element_addr: int, publish_addr: int, app_key_index: int, model_id: int, ttl: int = 7):
        # Opcode 0x03
        payload = element_addr.to_bytes(2, 'little') + \
                  publish_addr.to_bytes(2, 'little') + \
                  (app_key_index & 0xFFF).to_bytes(2, 'little') + \
                  bytes([ttl, 0x00, 0x00]) + \
                  model_id.to_bytes(2, 'little')
        return 0x03, payload

    def model_subscription_add(self, element_addr: int, sub_addr: int, model_id: int):
        # Opcode 0x801B
        payload = element_addr.to_bytes(2, 'little') + \
                  sub_addr.to_bytes(2, 'little') + \
                  model_id.to_bytes(2, 'little')
        return 0x801B, payload
