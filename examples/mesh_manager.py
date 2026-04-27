import asyncio
import logging
import sys
from typing import Dict, List
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack

# 屏蔽繁杂的日志，只保留关键信息
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger('mesh_manager')
logger.setLevel(logging.INFO)

class MeshManager:
    def __init__(self, stack: MeshStack):
        self.stack = stack
        self.scanned_devices: Dict[str, dict] = {} # uuid_hex -> info
        self.target_addr = None
        self.app_key = b'\x02' * 16
        self.app_key_index = 0

        # 注册回调
        self.stack.bearer.on_unprovisioned_device = self._on_device_found
        self.stack.on_auth_needed = self._on_auth_prompt

    def _on_device_found(self, uuid, rssi, oob_info):
        uuid_hex = uuid.hex()
        if uuid_hex not in self.scanned_devices:
            self.scanned_devices[uuid_hex] = {'uuid': uuid, 'rssi': rssi}
            # 这里的打印不会干扰输入，因为我们会手动刷新菜单
    
    async def _on_auth_prompt(self, uuid, method):
        print(f"\n[认证] 设备 {uuid.hex()} 请求认证！")
        pin = await asyncio.to_thread(input, "请输入设备显示的 PIN 码: ")
        try:
            await self.stack.resume_provisioning_with_pin(uuid, int(pin))
        except ValueError:
            print("错误: PIN 码必须是数字")

    async def show_menu(self):
        while True:
            print("\n" + "="*40)
            print("   Bluetooth Mesh 1.1 全功能管理终端")
            print("="*40)
            print(f" 当前目标: {f'0x{self.target_addr:04x}' if self.target_addr else '未设置'}")
            print("-" * 40)
            print(" 1. 扫描未配网设备 (Local Scan)")
            print(" 2. 开始本地配网 (Local Provision)")
            print(" 3. 远程扫描 (Remote Scan via node)")
            print(" 4. 远程配网 (Remote Provision via node)")
            print(" 5. 查看已配网节点 (Nodes)")
            print(" 6. 锁定操作目标 (Target)")
            print(" 7. 基础控制 - 开灯 (ON)")
            print(" 8. 基础控制 - 关灯 (OFF)")
            print(" 9. 查询当前状态 (Get Status)")
            print(" 10. 退出 (Quit)")
            print("-" * 40)
            
            choice = await asyncio.to_thread(input, "请选择操作 [1-10]: ")
            
            if choice == '1':
                await self.scan_flow()
            elif choice == '2':
                await self.provision_flow()
            elif choice == '3':
                await self.remote_scan_flow()
            elif choice == '4':
                await self.remote_provision_flow()
            elif choice == '5':
                self.list_nodes()
            elif choice == '6':
                await self.target_flow()
            elif choice == '7':
                await self.control_onoff(True)
            elif choice == '8':
                await self.control_onoff(False)
            elif choice == '9':
                await self.get_status()
            elif choice == '10':
                break
            else:
                print("无效选择")

    async def remote_scan_flow(self):
        if not self.target_addr:
            print("错误: 请先设置目标地址（充当中继的节点）")
            return
        
        self.scanned_devices.clear()
        print(f"\n指令已下发，正在通过 {self.target_addr:04x} 进行远程扫描...")
        
        def on_remote_report(src, uuid, rssi, oob):
            uid_hex = uuid.hex()
            if uid_hex not in self.scanned_devices:
                self.scanned_devices[uid_hex] = {'uuid': uuid, 'rssi': rssi}
                print(f" [发现远端设备] UUID: {uid_hex} | RSSI: {rssi}dBm")

        self.stack.rp_client.on_scan_report = on_remote_report
        opcode, payload = self.stack.rp_client.scan_start(timeout=10)
        await self.stack.send_model_message(self.target_addr, self.stack.rp_client, opcode, payload)
        await asyncio.sleep(10.0)
        print("\n远程扫描结束。")

    async def remote_provision_flow(self):
        if not self.target_addr:
            print("错误: 请先设置目标地址（中继节点）")
            return
        if not self.scanned_devices:
            print("错误: 请先执行远程扫描")
            return

        idx_str = await asyncio.to_thread(input, "选择要配网的远端设备编号: ")
        try:
            idx = int(idx_str)
            uuid_hex = list(self.scanned_devices.keys())[idx]
            uuid_bytes = self.scanned_devices[uuid_hex]['uuid']
            
            print(f"\n正在通过 {self.target_addr:04x} 启动远程配网: {uuid_hex}...")
            await self.stack.remote_provision_device(self.target_addr, uuid_bytes)
            print("\n[提示] 远程配网已结束，请检查 Nodes 列表。")
        except (ValueError, IndexError, Exception) as e:
            print(f"操作失败: {e}")

    async def scan_flow(self):
        self.scanned_devices.clear()
        print("\n正在扫描未配网设备 (持续 5 秒)...")
        await asyncio.sleep(5.0)
        if not self.scanned_devices:
            print("未发现新设备。")
        else:
            print("\n发现以下设备:")
            for i, (uid, info) in enumerate(self.scanned_devices.items()):
                print(f" [{i}] UUID: {uid} | RSSI: {info['rssi']}dBm")

    async def provision_flow(self):
        if not self.scanned_devices:
            print("错误: 请先执行扫描")
            return
        
        idx_str = await asyncio.to_thread(input, "选择要配网的设备编号: ")
        try:
            idx = int(idx_str)
            uuid_hex = list(self.scanned_devices.keys())[idx]
            device_info = self.scanned_devices[uuid_hex]
            
            print(f"\n正在启动配网: {uuid_hex}...")
            # 这个函数会触发认证回调，并自动触发后续的配置流
            await self.stack.provision_device(device_info['uuid'])
            print("\n[提示] 配网已触发。如果是 OOB 模式，请注意 PIN 码输入提示。")
            print("[提示] 流程结束后，请查看 'Nodes' 列表。")
        except (ValueError, IndexError):
            print("无效的编号")

    def list_nodes(self):
        nodes = self.stack.storage.get_nodes()
        print("\n已记录的节点列表:")
        if not nodes:
            print(" (空)")
        for n in nodes:
            print(f"  地址: {n['address']:04x} | UUID: {n['uuid'].hex()} | 名称: {n['name']}")

    async def target_flow(self):
        addr_str = await asyncio.to_thread(input, "输入目标节点的 4 位十六进制地址 (如 0002): ")
        try:
            self.target_addr = int(addr_str, 16)
            print(f"目标已设为: {self.target_addr:04x}")
        except ValueError:
            print("无效的地址格式")

    async def control_onoff(self, state: bool):
        if not self.target_addr:
            print("错误: 请先设置目标地址")
            return
        opcode, payload = self.stack.onoff_client.set(state, tid=getattr(self, '_tid', 0))
        self._tid = (getattr(self, '_tid', 0) + 1) % 256
        await self.stack.send_model_message(self.target_addr, self.stack.onoff_client, opcode, payload, app_key=self.app_key)
        print(f"指令已发送: {'ON' if state else 'OFF'}")

    async def get_status(self):
        if not self.target_addr:
            print("错误: 请先设置目标地址")
            return
        opcode, payload = self.stack.onoff_client.get()
        await self.stack.send_model_message(self.target_addr, self.stack.onoff_client, opcode, payload, app_key=self.app_key)
        print("状态查询已发送，等待回复...")

async def main():
    # 自动识别 HCI 端口
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:1'
    
    async with await open_transport(transport_path) as (hci_source, hci_sink):
        device = Device.with_hci('Mesh-Manager', '00:00:00:00:00:00', hci_source, hci_sink)
        await device.power_on()
        
        # 初始化
        net_key = b'\x01' * 16
        stack = MeshStack(device, net_key, 0x0001)
        await stack.start()
        
        # 确保本地 AppKey 加载
        stack.upper_transport.add_app_key(0, b'\x02' * 16)

        manager = MeshManager(stack)
        await manager.show_menu()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
