from ..access import Model
import logging

logger = logging.getLogger(__name__)

class RemoteProvisioningClient(Model):
    """
    Remote Provisioning Client Model (Model ID: 0x0004)
    Used to provision devices through a remote node.
    """
    MODEL_ID = 0x0004
    
    def __init__(self):
        super().__init__(self.MODEL_ID)
        # Register standard v1.1 Opcodes
        self.register_handler(0x8051, self._handle_scan_status)
        self.register_handler(0x8052, self._handle_scan_report)
        self.register_handler(0x8056, self._handle_link_status)
        self.register_handler(0x8057, self._handle_link_report)
        self.register_handler(0x8059, self._handle_pdu_outbound_report)
        self.register_handler(0x805A, self._handle_pdu_report)

        self.on_scan_report = None
        self.on_link_status = None
        self.on_pdu_report = None
        self.on_pdu_outbound_report = None

    # --- Handlers for Responses ---

    def _handle_pdu_outbound_report(self, src, payload):
        # Outbound PDU Count(1)
        count = payload[0]
        logger.debug(f"Remote PDU Outbound Report from {src:04x}: Count={count}")
        if self.on_pdu_outbound_report:
            self.on_pdu_outbound_report(src, count)

    def _handle_scan_status(self, src, payload):
        status = payload[0]
        scan_limit = payload[1]
        timeout = payload[2]
        logger.info(f"Remote Scan Status from {src:04x}: Status={status}, Limit={scan_limit}, Timeout={timeout}")

    def _handle_scan_report(self, src, payload):
        # RSSI(1) | UUID(16) | OOB(2)
        rssi = int.from_bytes(payload[0:1], 'big', signed=True)
        uuid = payload[1:17]
        oob = payload[17:19]
        logger.info(f"Remote Scan Report via {src:04x}: UUID={uuid.hex()}, RSSI={rssi}")
        if self.on_scan_report:
            self.on_scan_report(src, uuid, rssi, oob)

    def _handle_link_status(self, src, payload):
        status = payload[0]
        link_state = payload[1]
        logger.info(f"Remote Link Status from {src:04x}: Status={status}, State={link_state}")
        if self.on_link_status:
            self.on_link_status(src, status, link_state)

    def _handle_link_report(self, src, payload):
        logger.info(f"Remote Link Report from {src:04x}")

    def _handle_pdu_report(self, src, payload):
        # Inbound PDU Count(1) | Provisioning PDU(v)
        inbound_count = payload[0]
        pdu = payload[1:]
        if self.on_pdu_report:
            self.on_pdu_report(src, pdu)

    # --- Command Methods ---

    def scan_start(self, limit: int = 0, timeout: int = 10, uuid: bytes = None):
        """Starts remote scanning on the server node."""
        payload = bytes([limit, timeout])
        if uuid:
            payload += uuid
        return 0x804F, payload

    def scan_stop(self):
        """Stops remote scanning."""
        return 0x8050, b''

    def link_open(self, uuid: bytes):
        """Opens a remote provisioning link to a device UUID."""
        return 0x8054, uuid

    def link_close(self, reason: int = 0x00):
        """Closes the remote provisioning link."""
        return 0x8055, bytes([reason])

    def pdu_send(self, outbound_count: int, pdu: bytes):
        """Sends a Provisioning PDU encapsulated for remote delivery."""
        return 0x8058, bytes([outbound_count]) + pdu
