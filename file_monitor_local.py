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
    prev = "0"*64
    for i, e in enumerate(entries):
        payload = f"{e['timestamp']}|{e['event_type']}|{e['data']}|{e['prev_hash']}".encode()
        if hashlib.sha256(payload).hexdigest() != e["hash"] or e["prev_hash"] != prev:
            print(f"[!!] Tamper at entry {i}"); return False
        prev = e["hash"]
    print("[OK] Chain OK. Final digest:", prev); return True

# Initialize queue and list to store file events
event_q, file_events, chain = queue.Queue(), [], []
last = ["0"*64]

# Folder to monitor for file changes
FOLDER_OBSERVED = str(Path.home() / "Downloads")  # adjust to any folder

# Handler to detect changes to observed folder
class Handler(FileSystemEventHandler):
    # Handle file creation event
    def on_created(self, event):  
        if not event.is_directory: 
            fe = FileEvent(now_sgt_iso(),"created", event.src_path)
            event_q.put(fe)
            file_events.append(fe)
            ce = ChainEntry.create("file_event", asdict(fe), last[0])
            chain.append(asdict(ce)) 
            last[0] = ce.hash
    # Handle file modification event
    def on_modified(self, event):
        if not event.is_directory: 
            fe = FileEvent(now_sgt_iso(),"modified", event.src_path)
            event_q.put(fe)
            file_events.append(fe)
            ce = ChainEntry.create("file_event", asdict(fe), last[0])
            chain.append(asdict(ce)) 
            last[0] = ce.hash
    # Handle file deletion event
    def on_deleted(self, event):  
        if not event.is_directory: 
            fe = FileEvent(now_sgt_iso(),"deleted", event.src_path)
            event_q.put(fe)
            file_events.append(fe)
            ce = ChainEntry.create("file_event", asdict(fe), last[0])
            chain.append(asdict(ce)) 
            last[0] = ce.hash
    # Handle file movement event
    def on_moved(self, event):    
        if not event.is_directory: 
            fe = FileEvent(now_sgt_iso(),"moved", event.src_path, event.dest_path)
            event_q.put(fe)
            file_events.append(fe)
            ce = ChainEntry.create("file_event", asdict(fe), last[0])
            chain.append(asdict(ce)) 
            last[0] = ce.hash

# Print the folder being observed
print(f"Observing: {FOLDER_OBSERVED}")

# Create observer and schedule handler
observer = Observer()
observer.schedule(Handler(), FOLDER_OBSERVED, recursive=True)
observer.start()
try:
    while True:
        try:
            ev = event_q.get(timeout=0.5)
            file_events.append(ev)
            print(ev)
        except queue.Empty:
            pass
except KeyboardInterrupt:
    observer.stop() 
    observer.join()

    # Output Chain Event Log to JSON file
    out = Path("event_log.json"); out.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out}"); verify_chain(json.loads(out.read_text()))
