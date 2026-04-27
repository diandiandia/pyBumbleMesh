import asyncio
import logging
import sys
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack
from bumble_mesh.models.config import ConfigClient
from bumble_mesh.provisioning import ProvisioningState

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger(__name__)

async def main():
    # 允许通过命令行指定 hci 编号，例如: python -m examples.interactive_provisioner hci-socket:0
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:0'
    
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            device = Device.with_hci('Bumble-Provisioner', '00:00:00:00:00:00', hci_source, hci_sink)
            await device.power_on()
            
            local_address = device.public_address
            print(f"--- 适配器 [{transport_path}] 就绪: {local_address} ---")

            # 初始化协议栈
            net_key = b'\x01' * 16
            stack = MeshStack(device, net_key, 0x0001)
            
            # 注册配置客户端
            config_client = ConfigClient()
            stack.access.register_model(config_client)
            
            # 启动协议栈
            await stack.start()

            # 定时打印心跳，确认扫描器活着
            async def heartbeat():
                while True:
                    await asyncio.sleep(2)
                    print(f"  [心跳] 累计接收 HCI 信号总数: {stack.bearer.pkt_count}")
            asyncio.create_task(heartbeat())
            
            # --- 1. 扫描阶段 ---
            discovered_devices = []
            
            def on_device_found(uuid, rssi, oob):
                if not any(d[0] == uuid for d in discovered_devices):
                    discovered_devices.append((uuid, rssi, oob))
                    print(f"  [发现] UUID: {uuid.hex()} | RSSI: {rssi}")

            stack.bearer.on_unprovisioned_device = on_device_found
            
            print("\n正在扫描附近的 Mesh 设备 (15秒)...")
            await asyncio.sleep(15)
            
            if not discovered_devices:
                print("未发现任何未配网设备。")
                print("提示：如果心跳包数在增加但搜不到 Mesh，请尝试切换到另一个适配器 (hci-socket:1)。")
                return

            # --- 2. 展示列表 ---
            print("\n" + "="*50)
            print(f"{'编号':<5} {'UUID':<35} {'RSSI':<5}")
            print("-" * 50)
            for i, (uuid, rssi, oob) in enumerate(discovered_devices):
                print(f"{i:<5} {uuid.hex():<35} {rssi:<5}")
            print("="*50)

            # --- 3. 用户选择 ---
            try:
                selection = input("\n请输入想要配网的设备编号 (或输入 'q' 退出): ")
                if selection.lower() == 'q': return
                idx = int(selection)
                target_uuid, _, _ = discovered_devices[idx]
                
                auth_str = input("请输入 AuthValue (16字节十六进制，直接回车使用全0): ").strip()
                try:
                    auth_value = bytes.fromhex(auth_str) if auth_str else b'\x00' * 16
                    if len(auth_value) != 16:
                        print("错误：AuthValue 必须是 16 字节（32个十六进制字符）")
                        return
                except ValueError:
                    print("错误：请输入有效的十六进制字符串")
                    return
            except (ValueError, IndexError):
                print("无效的选择。")
                return

            # --- 4. 执行配网 ---
            print(f"\n开始为设备 {target_uuid.hex()} 进行配网...")
            provisioning_done = asyncio.Event()
            
            # 劫持状态检查
            original_handle_pdu = stack._on_bearer_pdu
            def on_pdu_monitored(pdu):
                original_handle_pdu(pdu)
                for s in stack.provisioning_states.values():
                    if s.state == ProvisioningState.COMPLETE: provisioning_done.set()
            
            stack.bearer.on_pdu = on_pdu_monitored
            await stack.provision_device(target_uuid, auth_value=auth_value)
            
            try:
                print("正在交换密钥...")
                await asyncio.wait_for(provisioning_done.wait(), timeout=30.0)
                print("配网成功！")
            except asyncio.TimeoutError:
                print("配网超时。")

            print("\n运行中，按 Ctrl+C 退出。")
            await asyncio.get_event_loop().create_future()

    except Exception as e:
        logger.error(f"发生错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())
