import asyncio
import logging
import sys
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
# 开启 DEBUG 以便看到详细的 PB-ADV 交互
logging.getLogger('bumble_mesh.pb_adv').setLevel(logging.DEBUG)
logger = logging.getLogger(__name__)

async def main():
    transport_path = 'hci-socket:0' if len(sys.argv) < 2 else sys.argv[1]
    
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            device = Device.with_hci('Bumble-Provisioner', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
            await device.power_on()
            
            # 初始化 Mesh 协议栈
            net_key = b'\x01' * 16
            provisioner_address = 0x0001
            stack = MeshStack(device, net_key, provisioner_address)
            
            # 记录已经发现的设备，防止重复触发
            discovered_uuids = set()

            def on_device_found(uuid, rssi, oob):
                if uuid not in discovered_uuids:
                    discovered_uuids.add(uuid)
                    logger.info(f"!!! DISCOVERED NEW DEVICE: {uuid.hex()} !!!")
                    # 自动开始配网
                    asyncio.create_task(stack.provision_device(uuid))

            stack.bearer.on_unprovisioned_device = on_device_found
            
            await stack.start()
            logger.info("Scanner/Provisioner is running. Waiting for Unprovisioned Beacons...")

            # 保持运行
            await asyncio.get_event_loop().create_future()

    except Exception as e:
        logger.error(f"Error: {e}")

if __name__ == '__main__':
    asyncio.run(main())
