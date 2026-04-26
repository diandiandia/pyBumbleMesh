import asyncio
import logging
import sys
import os
from bumble.device import Device
from bumble.transport import open_transport
from bumble_mesh.stack import MeshStack
from bumble_mesh.models.config import ConfigClient
from bumble_mesh.provisioning import ProvisioningState

# Configure logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

async def main():
    transport_path = 'hci-socket:0' if len(sys.argv) < 2 else sys.argv[1]
    
    try:
        async with await open_transport(transport_path) as (hci_source, hci_sink):
            device = Device.with_hci('Auto-Tester', '00:00:00:00:00:00', hci_source, hci_sink)
            await device.power_on()
            
            local_address = device.public_address
            logger.info(f"--- Controller Ready: {local_address} ---")

            # Initialize Stack (clear DB for clean test)
            if os.path.exists("mesh_database.db"):
                os.remove("mesh_database.db")
            
            net_key = b'\x01' * 16
            stack = MeshStack(device, net_key, 0x0001)
            config_client = ConfigClient()
            stack.access.register_model(config_client)
            
            await stack.start()
            
            # --- Auto-Scan ---
            target_uuid = None
            found_event = asyncio.Event()
            
            def on_device_found(uuid, rssi, oob):
                nonlocal target_uuid
                if target_uuid is None:
                    target_uuid = uuid
                    logger.info(f"!!! AUTO-TEST: Found target {uuid.hex()} !!!")
                    found_event.set()

            stack.bearer.on_unprovisioned_device = on_device_found
            
            logger.info("Scanning for 15 seconds...")
            try:
                await asyncio.wait_for(found_event.wait(), timeout=15.0)
            except asyncio.TimeoutError:
                logger.error("No devices found during scan.")
                return

            # --- Auto-Provision ---
            logger.info(f"Starting auto-provisioning for {target_uuid.hex()}...")
            
            provisioning_done = asyncio.Event()
            original_handle_pdu = stack._on_bearer_pdu
            
            def on_pdu_monitored(pdu):
                original_handle_pdu(pdu)
                for session in stack.provisioning_states.values():
                    if session.state == ProvisioningState.COMPLETE:
                        provisioning_done.set()
                    elif session.state == ProvisioningState.FAILED:
                        logger.error("Provisioning State Machine FAILED.")
                        sys.exit(1)
            
            stack.bearer.on_pdu = on_pdu_monitored
            await stack.provision_device(target_uuid)
            
            try:
                logger.info("Waiting for protocol handshake...")
                await asyncio.wait_for(provisioning_done.wait(), timeout=40.0)
                logger.info("CORE HANDSHAKE SUCCESSFUL!")
            except asyncio.TimeoutError:
                logger.error("Provisioning timed out.")
                sys.exit(1)

            # --- Auto-Config ---
            addr = 0x0002 # First node address
            logger.info(f"Sending AppKeyAdd to 0x{addr:04x}...")
            app_key = b'\x02' * 16
            opcode, payload = config_client.appkey_add(0, 0, app_key)
            await stack.send_model_message(addr, config_client, opcode, payload, app_key=b'\x00'*16)
            
            logger.info("Test completed. Closing in 5 seconds...")
            await asyncio.sleep(5)
            sys.exit(0)

    except Exception as e:
        logger.error(f"Test Fatal Error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(main())
