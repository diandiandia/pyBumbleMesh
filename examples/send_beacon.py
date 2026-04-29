import asyncio
from bumble.device import Device
from bumble.transport import open_transport
from bumble.hci import (
    HCI_LE_Set_Advertising_Parameters_Command,
    HCI_LE_Set_Advertising_Data_Command,
    HCI_LE_Set_Advertising_Enable_Command,
    Address
)

async def main():
    transport = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:1'
    async with await open_transport(transport) as (hci_source, hci_sink):
        device = Device.with_hci('Beacon', '00:00:00:00:00:00', hci_source, hci_sink)
        await device.power_on()

        await device.host.send_command(HCI_LE_Set_Advertising_Parameters_Command(
            advertising_interval_min=0x00a0,
            advertising_interval_max=0x00a0,
            advertising_type=HCI_LE_Set_Advertising_Parameters_Command.AdvertisingType.ADV_NONCONN_IND,
            own_address_type=0,
            peer_address_type=0,
            peer_address=Address.ANY,
            advertising_channel_map=7,
            advertising_filter_policy=0
        ))

        uuid = bytes.fromhex('AABBCCDDEEFF00112233445566778899')
        beacon = b'\x00' + uuid + b'\x00\x00'
        ad_data = bytes([len(beacon) + 1, 0x2B]) + beacon

        await device.host.send_command(HCI_LE_Set_Advertising_Data_Command(advertising_data=ad_data))
        await device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=1))
        print(f'Sent beacon UUID: {uuid.hex()}')

        # Flash for 3 seconds
        for _ in range(30):
            await asyncio.sleep(0.05)
            await device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=1))
        await asyncio.sleep(3)
        await device.host.send_command(HCI_LE_Set_Advertising_Enable_Command(advertising_enable=0))
        print('Done')

if __name__ == '__main__':
    import sys
    asyncio.run(main())
