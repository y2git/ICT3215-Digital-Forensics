import time, hashlib, queue, os, datetime as dt, json
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from typing import Optional, Dict, List

SGT = dt.timezone(dt.timedelta(hours=8))
def now_sgt_iso(): return dt.datetime.now(SGT).isoformat()

# Data class to represent a file event
@dataclass
class FileEvent:
    timestamp: str
    source: str # "USB" or "Local"
    action: str # e.g., "created", "modified", "deleted", "moved"
    src_path: str # source path of the file
    dest_path: Optional[str] = None # destination path for moved files

# Data class for blockchain-style chain entries
@dataclass
class ChainEntry:
    timestamp: str
    event_type: str
    data: Dict
    prev_hash: str
    hash: str
    @staticmethod
    def create(event_type, data, prev_hash):
        ts = now_sgt_iso()
        payload = f"{ts}|{event_type}|{data}|{prev_hash}".encode()
        h = hashlib.sha256(payload).hexdigest()
        return ChainEntry(ts, event_type, data, prev_hash, h)

# Function to compute SHA256 hash of file to verify integrity
def file_sha256(path):
    try:
        # Compute SHA256 hash
        h = hashlib.sha256()
        # Read file in chunks to avoid memory issues with large files
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk) # Read file in 8KB chunks
        return h.hexdigest() # Return hexadecimal digest of hash
    except Exception:
        return None

# Function to verify chain integrity
def verify_chain(entries: List[Dict]) -> bool:
    previous_hash = "0"*64 # initial hash
    for i, event in enumerate(entries):
        payload = f"{event['timestamp']}|{event['event_type']}|{event['data']}|{event['prev_hash']}".encode() # get the payload to hash
        if hashlib.sha256(payload).hexdigest() != event["hash"] or event["prev_hash"] != previous_hash: # verify hash and previous hash
            print(f"[!!] Tamper at entry {i}")
            return False
        previous_hash = event["hash"] # update previous hash
    print("[OK] Chain OK. Final digest:", previous_hash) 
    return True

# Initialize queue and list to store file events
event_q, file_events, chain = queue.Queue(), [], []
last = ["0"*64]
# Monitor Local file changes
LOCAL_FOLDER = str(Path.home() / "Downloads") 
# Monitor USB file changes
USB_MOUNT = "D:\\"  # change to your USB letter
#Track recently deleted files to determine if it was moved instead
recent_deletes = {}
MOVE_WINDOW = 1.0 # 1 second window to consider a delete as part of a move

# Handler to detect changes to observed folder
class Handler(FileSystemEventHandler):
    def __init__(self, q, source):
        super().__init__()
        self.q = q
        self.source = source
    # Handle logging the events
    def record_event(self, file_event: FileEvent):
        event_q.put(file_event)
        file_events.append(file_event)
        chain_entry = ChainEntry.create("file_event", asdict(file_event), last[0])
        chain.append(asdict(chain_entry)) 
        last[0] = chain_entry.hash
        print(f"[{file_event.action.upper()}]", file_event.src_path, "->" if file_event.dest_path else "", file_event.dest_path or "")
    # Handle file creation event
    def on_created(self, event):  
        if not event.is_directory: 
            for old_path, t in list(recent_deletes.items()):
                if (time.time() - t < MOVE_WINDOW) and (os.path.basename(old_path) == os.path.basename(event.src_path)):
                    file_event = FileEvent(now_sgt_iso(), self.source, "moved", old_path, event.src_path)
                    self.record_event(file_event)
                    recent_deletes.pop(old_path, None)
                    return
            # Otherwise, normal create
            file_event = FileEvent(now_sgt_iso(), self.source, "created", event.src_path)
            self.record_event(file_event)
    # Handle file modification event
    def on_modified(self, event):
        if not event.is_directory: 
            file_event = FileEvent(now_sgt_iso(), self.source, "modified", event.src_path)
            self.record_event(file_event)
    # Handle file deletion event
    def on_deleted(self, event):  
        if not event.is_directory: 
            recent_deletes[event.src_path] = time.time() # Add the recently deleted files to this list so it can be checked if the file was moved instead of permanently deleted
            file_event = FileEvent(now_sgt_iso(), self.source, "deleted", event.src_path)
            self.record_event(file_event)
    # Handle file movement event
    def on_moved(self, event):    
        if not event.is_directory: 
            file_event = FileEvent(now_sgt_iso(),"moved", event.src_path, event.dest_path)
            self.record_event(file_event)

# Create Local Observer
obs_local = Observer() 
obs_local.schedule(Handler(event_q, "Local"), LOCAL_FOLDER, recursive=True)
obs_local.start()
print(f"[*] Monitoring Local={LOCAL_FOLDER}")

# Create USB Observer
obs_usb = None
#obs_usb = Observer()
#obs_usb.schedule(Handler(event_q, "USB"), USB_MOUNT, recursive=True)
#obs_usb.start()
if USB_MOUNT and os.path.exists(USB_MOUNT):
    try:
        obs_usb = Observer()
        obs_usb.schedule(Handler(event_q, "USB"), USB_MOUNT, recursive=True)
        obs_usb.start()
        print(f"[*] Monitoring USB: {USB_MOUNT}")
    except Exception as e:
        print(f"[!] Failed to monitor USB {USB_MOUNT}: {e}")
        obs_usb = None

# Print message
print("[*] ... Ctrl+C to stop\n")

try:
    while True:
        try:
            event = event_q.get(timeout=0.5)
            file_events.append(event)
            print(event)
        except queue.Empty:
            pass
except KeyboardInterrupt:
    print("\n[*] Stopping monitors...")
    obs_local.stop()
    obs_local.join()

    # Only stop USB observer if it was actually started
    if obs_usb:
        obs_usb.stop()
        obs_usb.join()

    # Output Chain Event Log to JSON file
    out = Path("event_log.json"); out.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out}"); verify_chain(json.loads(out.read_text()))
