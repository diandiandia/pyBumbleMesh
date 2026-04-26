import asyncio
import logging
import sys
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack
from bumble_mesh.models.remote_provisioning import RemoteProvisioningClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

async def main():
    # 1. 硬件初始化 (Hardware Initialization)
    # 在 Raspberry Pi 上通常是 'hci-socket:0'
    transport_path = 'hci-socket:0' if len(sys.argv) < 2 else sys.argv[1]
    
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            logger.info(f"Connecting to Bluetooth Controller: {transport_path}")
            device = Device.with_hci('Bumble-Mesh', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
            await device.power_on()
            
            # 2. 初始化 Mesh 协议栈 (Initialize Mesh Stack)
            # 这里的 NetKey 和地址在实际组网后会由配置器分配
            net_key = b'\x01' * 16
            provisioner_address = 0x0001
            stack = MeshStack(device, net_key, provisioner_address)
            
            # 3. 注册远程配置模型
            rp_client = RemoteProvisioningClient()
            stack.access.register_model(rp_client)
            
            # 启动协议栈
            await stack.start()
            logger.info("Mesh Stack is running...")

            # 4. 演示：向中继节点 (Relay Node) 发送远程扫描指令
            # 假设 0x0002 是一个已经组网且支持 Remote Provisioning Server 的节点
            relay_addr = 0x0002
            logger.info(f"Triggering Remote Scan on node 0x{relay_addr:04x}...")
            
            opcode, payload = rp_client.scan_start(relay_addr)
            await stack.send_model_message(relay_addr, rp_client, opcode, payload)
            
            # 保持运行以接收来自 Pi 的扫描报告
            await asyncio.get_event_loop().create_future()

    except Exception as e:
        logger.error(f"Failed to start: {e}")

if __name__ == '__main__':
    asyncio.run(main())
