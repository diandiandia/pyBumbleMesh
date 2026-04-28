import os
import json
import logging
import logging.config

def setup_logging(default_path='logging_config.json', default_level=logging.INFO):
    """
    Setup logging configuration
    """
    path = default_path
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = json.load(f)
        logging.config.dictConfig(config)
        # 打印绝对路径方便调试
        log_file = config.get('handlers', {}).get('file', {}).get('filename', 'provisioning_debug.log')
        print(f"[*] 全局日志配置已加载: {os.path.abspath(log_file)}")
    else:
        logging.basicConfig(level=default_level)
        print("[!] 未找到日志配置文件，使用默认配置。")
