---
title: pyBumbleMesh-BlueZ Compatibility Guide
description: Known differences and fixes for making pyBumbleMesh work with BlueZ test-mesh/bluetooth-meshd
---

# pyBumbleMesh-BlueZ Compatibility

## Key Technical Details

### AID Calculation (Mesh Spec 4.2.6 vs 4.2.7)
BlueZ computes AppKey AID using `k4()`, NOT k2. The Mesh Spec Section 4.2.7 defines:
- `salt = AES-CMAC(ZERO, "smk4")`
- `t = AES-CMAC(salt, AppKey)`
- `result = AES-CMAC(t, "id6" || 0x01)`
- `AID = result[15] & 0x3F`

pyBumbleMesh originally used `k2(app_key, b'\x00')[15] & 0x3F` which is WRONG. Always use k4 for AppKey AID, k2 is for NetKey NID only. Add k4() to crypto.py.

### Remote Provisioning Uses DevKey (not AppKey)
BlueZ's `prov-initiator.c` checks:
```c
if (app_idx != APP_IDX_DEV_REMOTE && app_idx != APP_IDX_DEV_LOCAL)
    return true;  // reject non-DevKey messages
```
All Remote Provisioning messages (Scan Start/Stop, Link Open/Close, PDU Send/Report) MUST use DevKey encryption (AKF=0). In `send_model_message`, MODEL_ID 0x0005 (RemoteProvisioningClient) must go through the DevKey branch (same as ConfigClient 0x0001).

### AES-CMAC: Don't replace Bumble's implementation
Bumble's `aes_cmac` produces NID=0x3d for all-zero NetKey, matching BlueZ. Do NOT replace it with a "standard" AES-CMAC implementation — that breaks provisioning confirmation verification (confirmation-failed).

### BlueZ Unsegmented Message ASZMIC Behavior
BlueZ forces `szmict=false` (aszmic=0) for unsegmented messages. The transport header's ASZMIC bit is ONLY parsed for segmented messages. Never use aszmic=1/mic_len=8 for unsegmented messages when communicating with BlueZ.

### Segmented Message ASZMIC Consistency
`encrypt()` and `segment_pdu()` must use the same ASZMIC value. If encrypt uses aszmic=0/mic_len=4, segment_pdu's ASZMIC bit must also be 0 — otherwise BlueZ sees ASZMIC=1 in the segment header and expects an 8-byte MIC when only 4 bytes were appended.

### ConfirmationInputs: BlueZ includes Type bytes
BlueZ includes PDU Type bytes (0x00 for Invite, 0x01 for Capabilities, etc.) in the ConfirmationInputs calculation. pyBumbleMesh strips them with `pdu[1:]` which is correct — both sides must use the same convention. pyBumbleMesh's ConfirmationInputs format matches BlueZ's behavior.

### PB-ADV Transaction Sequence
When sending local public key in PB-ADV provisioning:
1. Send START PDU
2. Wait ~1.0s for device to process
3. Send Public Key (may be segmented)
The delay between START and Public Key is critical on Linux HCI controllers.

### AppKey Add: Must precede Model App Bind
AppKey must be sent AND acknowledged by the node before models can be bound. The AppKey Status response confirms the AppKey was stored by bluetooth-meshd.

### AppKey Add payload format
Access payload = opcode(0x00) + NetKeyIndex(3 bytes packed) + AppKey(16 bytes) = 20 bytes total, 19 bytes after opcode. BlueZ checks `if (size != 19) return true` — exact match required.
