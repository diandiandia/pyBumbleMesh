import logging
from typing import Dict, Callable, Optional, Type

logger = logging.getLogger(__name__)

class Message:
    """Base class for all Mesh Access messages."""
    def __init__(self, opcode: int, parameters: bytes = b''):
        self.opcode = opcode
        self.parameters = parameters

    def serialize(self) -> bytes:
        # Opcode serialization logic (1, 2, or 3 bytes)
        if self.opcode < 0x80:
            return bytes([self.opcode]) + self.parameters
        elif self.opcode < 0x10000:
            return self.opcode.to_bytes(2, 'big') + self.parameters
        else:
            return self.opcode.to_bytes(3, 'big') + self.parameters

class Model:
    """Base class for all Mesh Models (Client and Server)."""
    def __init__(self, model_id: int):
        self.model_id = model_id
        self.bound_app_keys: list[int] = []
        # Mapping: Opcode -> Handler Method
        self.handlers: Dict[int, Callable[[int, bytes], None]] = {}

    def register_handler(self, opcode: int, handler: Callable[[int, bytes], None]):
        self.handlers[opcode] = handler

    def handle_message(self, src: int, opcode: int, parameters: bytes):
        if opcode in self.handlers:
            self.handlers[opcode](src, parameters)
        else:
            logger.debug(f"Model {self.model_id:04x} has no handler for Opcode {opcode:04x}")

class AccessLayer:
    """
    Handles Mesh Models and Routes incoming messages based on Model ID and Opcode.
    """
    def __init__(self):
        # Mapping: ModelID -> Model instance
        self.models: Dict[int, Model] = {}

    def register_model(self, model: Model):
        self.models[model.model_id] = model
        logger.info(f"Registered Model: {model.model_id:04x}")

    def handle_pdu(self, src: int, dst: int, ad_key: int, payload: bytes):
        """
        Routes the decrypted Upper Transport PDU to the correct model.
        """
        # 1. Parse Opcode
        first_byte = payload[0]
        if (first_byte & 0x80) == 0:
            opcode = first_byte
            opcode_len = 1
        elif (first_byte & 0xC0) == 0x80:
            opcode = int.from_bytes(payload[:2], 'big')
            opcode_len = 2
        else:
            opcode = int.from_bytes(payload[:3], 'big')
            opcode_len = 3
        
        parameters = payload[opcode_len:]
        
        # 2. Dispatch to models
        # In a real implementation, a message might target multiple models or an element.
        # Here we route to all models that have a handler for this Opcode.
        found = False
        for model in self.models.values():
            if opcode in model.handlers:
                model.handle_message(src, opcode, parameters)
                found = True
        
        if not found:
            logger.warning(f"No model found to handle Opcode {opcode:04x} from {src:04x}")
