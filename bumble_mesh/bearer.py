import asyncio
import logging
from typing import Callable, Optional
from bumble.device import Device
from bumble.hci import (
    Address,
    HCI_LE_Set_Advertising_Parameters_Command,
    HCI_LE_Set_Advertising_Data_Command,
    HCI_LE_Set_Advertising_Enable_Command,
    OwnAddressType
)

logger = logging.getLogger(__name__)

class AdvBearer:
    def __init__(self, device: Device):
        self.device = device
        self.on_pdu: Optional[Callable[[bytes], None]] = None
        self.on_beacon: Optional[Callable[[bytes], None]] = None
        self.on_unprovisioned_device: Optional[Callable[[bytes, int, bytes], None]] = None
        self.on_secure_beacon: Optional[Callable[[bytes], None]] = None
        self.pkt_count = 0
        self.tx_lock = asyncio.Lock()

    async def start(self):
        self.device.on('advertisement', self._on_advertisement)
        await self.device.start_scanning(active=True)
        
        logger.info("Initializing Mesh Bearer...")
        own_addr_type = OwnAddressType.PUBLIC if self.device.public_address.is_public else OwnAddressType.RANDOM

        await self.device.host.send_command(
            HCI_LE_Set_Advertising_Parameters_Command(
                advertising_interval_min=0x0020,
                advertising_interval_max=0x0020,
                advertising_type=HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType.ADV_NONCONN_IND,
                own_address_type=own_addr_type,
                peer_address_type=0,
                peer_address=Address.ANY,
                advertising_channel_map=7,
                advertising_filter_policy=0
            )
        )
        # We start with advertising DISABLED to allow full scanning
        await self.device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=0))

    def _on_advertisement(self, advertisement):
        self.pkt_count += 1
        self._parse_ad_data(bytes(advertisement.data), advertisement.address, advertisement.rssi)

    def _parse_ad_data(self, data: bytes, address, rssi):
        i = 0
        while i < len(data):
            length = data[i]
            if length == 0: break
            if i + length + 1 > len(data): break
            ad_type = data[i+1]
            payload = data[i+2 : i+1+length]
            
            if ad_type in (0x29, 0x2A):
                if self.on_pdu: self.on_pdu(payload)
            elif ad_type == 0x2B:
                if len(payload) >= 19:
                    if payload[0] == 0x00:
                        if self.on_unprovisioned_device:
                            self.on_unprovisioned_device(payload[1:17], rssi, payload[17:19])
                    elif payload[0] == 0x01:
                        if self.on_secure_beacon:
                            self.on_secure_beacon(payload)
            i += 1 + length

    async def send_pdu(self, pdu: bytes, is_pb_adv: bool = True):
        async with self.tx_lock:
            ad_type = 0x29 if is_pb_adv else 0x2A
            ad_data = bytes([len(pdu) + 1, ad_type]) + pdu
            
            # --- "SHOTGUN" TRANSMIT PATTERN ---
            # Pulse the advertisement then immediately return to scanning.
            # This prevents the provisioner from being "deaf" while sending.
            await self.device.host.send_command(HCI_LE_Set_Advertising_Data_Command(advertising_data=ad_data))
            await self.device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=1))
            
            # Hold for a short burst (Mesh segments are tiny, 40ms is plenty for 3 channels)
            await asyncio.sleep(0.04)
            
            await self.device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=0))
            
            # Safety gap before next command or next RX
            await asyncio.sleep(0.01)
