from google.protobuf.internal import api_implementation
print(api_implementation.Type())
from enum import Enum

msg_id =0

class CASIC_HEADER(Enum):
    type_a = 0xBA
    type_b = 0xCE

class casic_class:
    def __init__(self, header, class_type, payload) -> None:
        
        self.header = header

        self.length = len(payload)
        
        assert self.length%4 == 0, "Payload length must be a multiple of 4"
        self.class_type = class_type
        
        msg_id = msg_id + 1
        self.msg_id = msg_id

        self.payload = payload

        self.checksum = self.checksum()
    
    def check_sum(self):
        checksum = (self.msg_id << 24) + (self.class_type << 16) + self.length
        for i in range(self.length/4):
            checksum = checksum + self.payload[i]
        return checksum

