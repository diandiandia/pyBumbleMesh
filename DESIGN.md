# pyBumbleMesh Design Document v2.0

## 1. 总体流程 (Overall Process)
实现从“零”到“控制远程设备”的完整链路，分为以下三个大阶段：

### 阶段 A：基础配网 (Standard Provisioning - PB-ADV)
这是将一个新设备（Unprovisioned Device）加入网络的过程。
1.  **Beaconing (发现)**: 监听 Unprovisioned Device Beacons。
2.  **Link Establishment (建连)**: 通过 PB-ADV 开启 Provisioning Link。
3.  **Provisioning Protocol (协议交换)**:
    - `Invite` / `Capabilities`: 邀请并获取设备能力。
    - `Start` / `Public Key`: 协商加密方式并交换公钥。
    - `Authentication`: 完成身份认证（如 Input/Output OOB）。
    - `Distribution`: 分发网络密钥 (NetKey)、单播地址 (Unicast Address) 和设备密钥 (DevKey)。
4.  **Completion**: 设备现在成为网络中的一个“节点 (Node)”。

### 阶段 B：配置与绑定 (Configuration & Binding)
设备入网后，默认只有基础通信能力，需要通过 **Configuration Client** 进行配置。
1.  **AppKey Add**: 向节点分发应用密钥。
2.  **Model App Bind**: 将特定的模型（如 Remote Provisioning Server）绑定到 AppKey。
3.  **Subscription/Publication Set**: 配置节点的发布和订阅地址。

### 阶段 C：远程配网 (Remote Provisioning - PB-Remote)
利用已入网的节点（作为中继）去配网它信号范围内的其他设备。
1.  **Remote Scan**: 指令 A 节点扫描附近的未配网设备。
2.  **Remote Link**: 通过 A 节点与目标设备 B 建立逻辑链路。
3.  **Tunneling**: 将 Provisioning PDU 封装在 Mesh 消息中，通过 A 节点透传给 B。

## 2. 模块切分 (Module Decomposition)
- `provisioning.py`: 实现完整的 Provisioning 状态机。
- `transport.py`: **关键更新** - 实现分段重组 (SAR)，因为配置消息通常较长。
- `models/config.py`: 实现 Configuration Client，用于添加 AppKey 和绑定模型。
- `models/remote_provisioning.py`: 完善远程配网模型。
