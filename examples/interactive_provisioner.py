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
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:1'
    
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
                selection = input("\n请输入编号，或直接粘贴 UUID (32位十六进制) 强制配网 (或输入 'q' 退出): ").strip()
                if selection.lower() == 'q': return
                
                if len(selection) == 32:
                    target_uuid = bytes.fromhex(selection)
                else:
                    idx = int(selection)
                    target_uuid, _, _ = discovered_devices[idx]
                
                print(f"目标 UUID: {target_uuid.hex()}")
                auth_str = input("请输入 AuthValue (16字节十六进制，pi1若未显示则直接回车): ").strip()
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
            
            async def check_provisioning_status():
                while not provisioning_done.is_set():
                    await asyncio.sleep(0.5)
                    for link_id, s in stack.provisioning_states.items():
                        if s.state == ProvisioningState.AUTH_INPUT:
                            print("\n" + "!"*20)
                            print("设备已激活！请查看 p1 (test-mesh) 屏幕显示的 PIN 码。")
                            pin_str = input("请输入该 PIN 码 (例如 123456): ").strip()
                            try:
                                pin = int(pin_str)
                                await stack.resume_provisioning_with_pin(target_uuid, pin)
                            except ValueError:
                                print("错误：请输入纯数字 PIN 码")
                        
                        if s.state == ProvisioningState.COMPLETE:
                            provisioning_done.set()
                        elif s.state == ProvisioningState.FAILED:
                            print("\n配网失败！请检查 AuthValue 是否正确或重试。")
                            provisioning_done.set()

            asyncio.create_task(check_provisioning_status())
            
            await stack.provision_device(target_uuid)
            
            try:
                print("正在进行安全握手 (交换公钥与身份验证)...")
                await asyncio.wait_for(provisioning_done.wait(), timeout=60.0)
                print("配网流程结束。")
            except asyncio.TimeoutError:
                print("配网超时。")

            print("\n运行中，按 Ctrl+C 退出。")
            await asyncio.get_event_loop().create_future()

    except Exception as e:
        logger.error(f"发生错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())
