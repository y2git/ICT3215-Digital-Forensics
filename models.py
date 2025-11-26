import hashlib
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional
from utils import now_sgt_iso

# Dataclass to create the class ChainEntry which is used to check for tampering
@dataclass
class ChainEntry:
    timestamp_sgt: str # the time of event
    event_type: str # the type of event
    data: Dict # the data of the event
    prev_hash: str # the previous hash
    hash: str # the current hash

    # Create a new ChainEntry whenever a new event is recorded
    @staticmethod 
    def create(event_type: str, data: Dict, prev_hash: str):
        timestamp = now_sgt_iso() # the time of event
        payload = f"{timestamp}|{event_type}|{data}|{prev_hash}".encode() # the information that will be hashed for integrity check
        h = hashlib.sha256(payload).hexdigest() # hashing the payload
        return ChainEntry(timestamp, event_type, data, prev_hash, h)

# Dataclass to represent file events
@dataclass
class FileEvent:
    timestamp_sgt: str # the time of event
    action: str # the action performed
    src_path: str # the source path of the file
    dest_path: Optional[str] = None # the destination path if moved
    file_hash: Optional[str] = None # the sha256 hash of the file
    source: str = "Local" # the source of the event (Local or USB)

# Dataclass to represent .exe events
@dataclass
class ExecEvent:
    timestamp_sgt: str # the time of event
    pid: int # the process id
    exe_path: str # the path of the executable
    cmdline: List[str] # the command line arguments
    username: Optional[str] = None # the user who executed the process
