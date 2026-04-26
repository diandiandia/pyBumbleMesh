# pyBumbleMesh

本项目旨在使用 [Bumble](https://github.com/google/bumble) 蓝牙栈实现 Bluetooth Mesh v1.1 功能，特别是 **远程配置 (Remote Provisioning / PB-Remote)**。

This project aims to implement Bluetooth Mesh v1.1 features using the [Bumble](https://github.com/google/bumble) Bluetooth stack, with a focus on **Remote Provisioning (PB-Remote)**.

## 核心目标 (Goals)
1.  **组网 (Networking)**: 使用 Bumble 驱动蓝牙设备建立 Mesh 网络。
2.  **配置 (Provisioning)**: 实现 Provisioner 角色，支持 PB-ADV 和 PB-Remote。
3.  **远程配置 (Remote Provisioning)**: 通过已组网的节点，对超出信号范围的设备进行远程配置。

## 项目结构 (Structure)
- `bumble_mesh/`: 核心代码库 (Core Stack)
    - `bearer.py`: 承载层 (Adv/Gatt Bearers)
    - `crypto.py`: 加密与密钥派生 (K-functions, AES-CCM)
    - `network.py`: 网络层 (PDU construction, encryption)
    - `access.py`: 应用层 (Opcode routing, Model base)
    - `provisioning.py`: 配置协议状态机 (Provisioning SM)
    - `models/`: Mesh 模型实现
        - `remote_provisioning.py`: 远程配置模型 (PB-Remote Models)
- `examples/`: 使用示例 (Example scripts)
- `DESIGN.md`: 详细设计文档 (Detailed design)

## 快速开始 (Quick Start)

### 安装依赖 (Install dependencies)
```bash
pip install -r requirements.txt
```

### 运行示例 (Run example)
```bash
python examples/remote_provisioner.py
```

## 实现进度 (Roadmap)
- [x] 核心加密算法 (Crypto foundations)
- [x] 承载层接口 (Bearer interface)
- [x] 网络层 PDU (Network PDU)
- [x] 远程配置模型定义 (Remote Provisioning Model definitions)
- [ ] 完整的配置协议状态机 (Complete Provisioning State Machine)
- [ ] 分段与重组 (Lower Transport SAR)
- [ ] 实际硬件测试 (Hardware integration tests)
