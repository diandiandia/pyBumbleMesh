import asyncio
import logging
import sys
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack
from bumble_mesh.models.config import ConfigClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

async def main():
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:1'
    
    async with await open_transport(transport_path) as (hci_source, hci_sink):
        device = Device.with_hci('Bumble-Shell', '00:00:00:00:00:00', hci_source, hci_sink)
        await device.power_on()
        
        # 初始化协议栈 (连接现有数据库)
        net_key = b'\x01' * 16
        stack = MeshStack(device, net_key, 0x0001)
        config_client = ConfigClient()
        stack.access.register_model(config_client)
        await stack.start()

        target_addr = None
        app_key = b'\x02' * 16
        app_key_index = 0

        # 将 AppKey 添加到本地协议栈（非常重要，否则无法解密发往应用层的消息）
        stack.upper_transport.add_app_key(app_key_index, app_key)

        # --- MODEL CALLBACKS ---
        def on_onoff(src, present, target, remaining):
            status = "ON" if present else "OFF"
            print(f"\n[STATUS] 节点 {src:04x} 当前状态: {status}")

        stack.onoff_client.on_onoff_status = on_onoff

        print("\n=== pyBumbleMesh 全功能配置与控制终端 ===")
        print("可用命令:")
        print("  nodes             - 查看已配网节点")
        print("  target <addr>     - 设置当前操作目标")
        print("  composition       - 获取并解析功能列表")
        print("  appkey-add        - 下发应用密钥 0")
        print("  bind <model_id>   - 绑定模型到密钥 0")
        print("  pub-set <model_id>- 设置模型自动上报状态给网关")
        print("  get               - 查询 Generic OnOff 状态")
        print("  on / off          - 开灯 / 关灯")
        print("  quit              - 退出")

        while True:
            cmd_line = await asyncio.to_thread(input, f"\nmesh({target_addr:04x if target_addr else 'none'})> ")
            parts = cmd_line.strip().split()
            if not parts: continue
            cmd = parts[0].lower()

            if cmd == 'nodes':
                nodes = stack.storage.get_nodes()
                print("\n已记录的节点列表:")
                for n in nodes:
                    print(f"  地址: {n['address']:04x} | UUID: {n['uuid'].hex()}")

            elif cmd == 'target':
                if len(parts) < 2:
                    print("用法: target <4位十六进制地址>")
                    continue
                target_addr = int(parts[1], 16)
                print(f"当前操作目标已设为: {target_addr:04x}")

            elif cmd == 'composition':
                if not target_addr:
                    print("错误: 请先使用 'target' 指定设备地址")
                    continue
                opcode, payload = stack.config_client.composition_data_get()
                await stack.send_model_message(target_addr, stack.config_client, opcode, payload)

            elif cmd == 'appkey-add':
                if not target_addr: continue
                opcode, payload = stack.config_client.appkey_add(0, app_key_index, app_key)
                await stack.send_model_message(target_addr, stack.config_client, opcode, payload)

            elif cmd == 'bind':
                if not target_addr or len(parts) < 2: continue
                model_id = int(parts[1], 16)
                opcode, payload = stack.config_client.model_app_bind(target_addr, app_key_index, model_id)
                await stack.send_model_message(target_addr, stack.config_client, opcode, payload)

            elif cmd == 'pub-set':
                if not target_addr or len(parts) < 2: continue
                model_id = int(parts[1], 16)
                # 设置发布地址为网关自己 (0x0001)
                opcode, payload = stack.config_client.model_publication_set(target_addr, 0x0001, app_key_index, model_id)
                await stack.send_model_message(target_addr, stack.config_client, opcode, payload)

            elif cmd == 'get':
                if not target_addr: continue
                opcode, payload = stack.onoff_client.get()
                # 使用 AppKey 0 加密
                await stack.send_model_message(target_addr, stack.onoff_client, opcode, payload, app_key=app_key)

            elif cmd in ('on', 'off'):
                if not target_addr: continue
                onoff = (cmd == 'on')
                opcode, payload = stack.onoff_client.set(onoff, tid=getattr(stack, '_tid', 0))
                stack._tid = (getattr(stack, '_tid', 0) + 1) % 256
                await stack.send_model_message(target_addr, stack.onoff_client, opcode, payload, app_key=app_key)

            elif cmd == 'quit':
                break
if __name__ == '__main__':
    asyncio.run(main())
