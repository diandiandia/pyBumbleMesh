import asyncio
import logging
import sys
from bumble.device import Device
from bumble.transport import open_transport
from bumble.hci import HCI_LE_Set_Scan_Parameters_Command, HCI_LE_Set_Scan_Enable_Command

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

async def main():
    transport_path = 'hci-socket:0' if len(sys.argv) < 2 else sys.argv[1]
    
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            print(f"--- 正在连接到 {transport_path} ---")
            device = Device.with_hci('Sniffer', 'F0:F1:F2:F3:F4:F5', hci_source, hci_sink)
            
            # 存活检查：读取本地版本
            from bumble.hci import HCI_Read_Local_Version_Information_Command
            response = await device.host.send_command(
                HCI_Read_Local_Version_Information_Command()
            )
            print(f"成功连接到控制器！版本: {response.hci_version}")

            await device.power_on()
            
            # 直接监听底层事件
            def on_hci_event(event):
                # 打印所有底层事件的名称
                print(f"[底层 HCI 事件] {event}")

            device.host.on('hci_event', on_hci_event)

            print("\n正在启动主动扫描...")
            # 我们直接手动发命令开启扫描，不依赖 device.start_scanning
            await device.host.send_command(
                HCI_LE_Set_Scan_Parameters_Command(
                    le_scan_type=HCI_LE_Set_Scan_Parameters_Command.ACTIVE_SCANNING,
                    le_scan_interval=0x0010,
                    le_scan_window=0x0010,
                    own_address_type=0,
                    scanning_filter_policy=0
                )
            )
            await device.host.send_command(HCI_LE_Set_Scan_Enable_Command(le_scan_enable=1, filter_duplicates=0))
            
            print("扫描命令已发出。如果看到 '[底层 HCI 事件] HCI_LE_Advertising_Report_Event'，说明硬件工作正常。")
            await asyncio.get_event_loop().create_future()

    except Exception as e:
        print(f"\n!!! 启动失败 !!! 原因可能如下:")
        print(f"1. 权限不足：请尝试使用 sudo。")
        print(f"2. 设备占用：请执行 'sudo hciconfig hci0 down'。")
        print(f"错误详情: {e}")

if __name__ == '__main__':
    # 注意：为了在脚本中导入，我们需要手动处理一下导入
    from bumble.hci import HCI_Read_Local_Version_Information_Command
    asyncio.run(main())
