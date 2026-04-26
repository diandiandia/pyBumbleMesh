import asyncio
import sys
from bumble.transport import open_transport

class SimpleSink:
    def on_packet(self, packet: bytes):
        print(f"  [信号捕获] RX ({len(packet)} 字节): {packet.hex()}")

async def main():
    transport_path = sys.argv[1] if len(sys.argv) > 1 else 'hci-socket:0'
    print(f"--- 终极 HCI 信号检测: {transport_path} ---")
    
    try:
        async with await open_transport(transport_path) as (source, sink):
            print("连接成功！正在等待数据包流...")
            
            # 使用一个对象而不是函数作为 Sink
            source.set_packet_sink(SimpleSink())
            
            # 手动发送开启扫描的命令
            print("正在强制开启底层扫描...")
            # HCI_LE_Set_Scan_Parameters (Active, 0x10, 0x10)
            sink.on_packet(bytes.fromhex("010b200701100010000000")) 
            # HCI_LE_Set_Scan_Enable (Enable=1, Filter=0)
            sink.on_packet(bytes.fromhex("010c20020100")) 

            # 保持运行 30 秒
            for i in range(30):
                await asyncio.sleep(1)
                if i % 5 == 0: print(f"已扫描 {i} 秒...")
                
    except Exception as e:
        print(f"错误: {e}")

if __name__ == '__main__':
    asyncio.run(main())
