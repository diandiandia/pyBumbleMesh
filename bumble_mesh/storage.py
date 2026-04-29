import sqlite3
import json
import logging
from typing import Optional, Dict, List

logger = logging.getLogger(__name__)

class MeshStorage:
    def __init__(self, db_path: str = "mesh_database.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # 1. Local Settings
            cursor.execute('''CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )''')
            # 2. Networks (NetKeys)
            cursor.execute('''CREATE TABLE IF NOT EXISTS networks (
                net_index INTEGER PRIMARY KEY,
                net_key BLOB,
                iv_index INTEGER
            )''')
            # 3. Nodes
            cursor.execute('''CREATE TABLE IF NOT EXISTS nodes (
                unicast_address INTEGER PRIMARY KEY,
                uuid BLOB,
                dev_key BLOB,
                name TEXT,
                composition_data BLOB
            )''')
            # 4. AppKeys
            cursor.execute('''CREATE TABLE IF NOT EXISTS app_keys (
                app_index INTEGER PRIMARY KEY,
                app_key BLOB
            )''')
            # 5. Node Models
            cursor.execute('''CREATE TABLE IF NOT EXISTS node_models (
                node_addr INTEGER,
                elem_addr INTEGER,
                model_id INTEGER,
                is_vendor INTEGER,
                PRIMARY KEY(node_addr, elem_addr, model_id)
            )''')
            conn.commit()

    # --- Settings Management ---
    def get_setting(self, key: str, default=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
            cursor.execute("SELECT value FROM settings WHERE key=?", (key,))
            row = cursor.fetchone()
            return row[0] if row else default

    def set_setting(self, key: str, value: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)")
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, str(value)))
            conn.commit()

    # --- Network Management ---
    def save_network(self, net_index: int, net_key: bytes, iv_index: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO networks (net_index, net_key, iv_index) VALUES (?, ?, ?)",
                         (net_index, net_key, iv_index))
            conn.commit()

    def get_networks(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT net_index, net_key, iv_index FROM networks")
            return [{"index": row[0], "key": row[1], "iv_index": row[2]} for row in cursor.fetchall()]

    # --- Node Management ---
    def save_node(self, address: int, uuid: bytes, dev_key: bytes, name: str = ""):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO nodes (unicast_address, uuid, dev_key, name) VALUES (?, ?, ?, ?)",
                         (address, uuid, dev_key, name))
            conn.commit()
            logger.info(f"Node {address:04x} saved to database.")

    def get_nodes(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT unicast_address, uuid, dev_key, name FROM nodes")
            return [{"address": row[0], "uuid": row[1], "dev_key": row[2], "name": row[3]} for row in cursor.fetchall()]

    # --- AppKey Management ---
    def save_app_key(self, app_index: int, app_key: bytes):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO app_keys (app_index, app_key) VALUES (?, ?)",
                         (app_index, app_key))
            conn.commit()

    def get_app_keys(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT app_index, app_key FROM app_keys")
            return [{"index": row[0], "key": row[1]} for row in cursor.fetchall()]

    # --- Model Management ---
    def save_node_model(self, node_addr: int, elem_addr: int, model_id: int, is_vendor: bool = False):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO node_models (node_addr, elem_addr, model_id, is_vendor) VALUES (?, ?, ?, ?)",
                         (node_addr, elem_addr, model_id, 1 if is_vendor else 0))
            conn.commit()

    def get_node_models(self, node_addr: int) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT elem_addr, model_id, is_vendor FROM node_models WHERE node_addr=?", (node_addr,))
            return [{"elem_addr": row[0], "model_id": row[1], "is_vendor": bool(row[2])} for row in cursor.fetchall()]
