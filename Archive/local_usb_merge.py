import time, hashlib, queue, os, datetime as dt, json, psutil, signal, sys
from dataclasses import dataclass, asdict
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path
from typing import Optional, Dict, List
import subprocess, json

SGT = dt.timezone(dt.timedelta(hours=8))
def now_sgt_iso():
    return dt.datetime.now(SGT).isoformat()
def now_sgt_str(): 
    return dt.datetime.now(SGT).strftime('%Y%m%dT%H%M%S')

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
@dataclass
class LifecycleEvent:
    timestamp: str
    status: str  # "tool_start" or "tool_stop"
    note: Optional[str] = None
def record_lifecycle(status: str, note: str = ""):
    e = LifecycleEvent(now_sgt_iso(), status, note)
    entry = ChainEntry.create("lifecycle_event", asdict(e), last[0])
    chain.append(asdict(entry))
    last[0] = entry.hash
    print(f"[LIFECYCLE] {status.upper()} @ {e.timestamp}")

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

# Get USB hardware and volume identification details
def get_usb_device_info(drive_letter: str):
    info = {"mount": drive_letter, "volume_label": None, "serial_number": None, "pnp_id": None}
    # Volume label & serial
    try:
        r = subprocess.run(["wmic","volume","where",f"DriveLetter='{drive_letter}'","get","Label,SerialNumber","/format:list"],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("Label="):        info["volume_label"] = line.split("=",1)[1].strip()
            if line.startswith("SerialNumber="): info["serial_number"] = line.split("=",1)[1].strip()
    except Exception: pass
    # PNP ID (VID/PID + device serial)
    try:
        r = subprocess.run(["wmic","diskdrive","where","MediaType='Removable Media'","get","PNPDeviceID","/format:list"],
                           capture_output=True, text=True)
        for line in r.stdout.splitlines():
            if line.startswith("PNPDeviceID="):
                info["pnp_id"] = line.split("=",1)[1].strip(); break
    except Exception: pass
    return info

print(json.dumps(get_usb_device_info("D:"), indent=2))

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
        try:
            info = get_usb_device_info("D:")
            print(json.dumps(info, indent=2))
        except Exception as e:
            print(f"[!] Could not get USB info: {e}")
    except Exception as e:
        print(f"[!] Failed to monitor USB {USB_MOUNT}: {e}")
        obs_usb = None

# Print message
print("[*] ... Ctrl+C to stop\n")
record_lifecycle("tool_start", "Monitoring initiated")

seen = set()
try:
    while True:
        # Process monitoring events currently not in event.log
        for p in psutil.process_iter(attrs=["pid","exe","cmdline"]):
            pid = p.info["pid"]
            if pid in seen: continue
            seen.add(pid)
            exe = p.info.get("exe")
            if exe and exe.lower().startswith(USB_MOUNT.lower()):
                print(f"[EXEC] PID={pid} EXE={exe} CMD={p.info.get('cmdline')}")

        # File monitoring events
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
    record_lifecycle("tool_stop", "Monitoring stopped by user")

    # Generate final digest file
    final_digest = {
        "timestamp": now_sgt_iso(),
        "final_hash": last[0],
        "total_events": len(chain)
    }
    Path("final_digest.json").write_text(json.dumps(final_digest, indent=2), encoding="utf-8")
    print(f"[OK] Wrote final digest (chain hash): {final_digest['final_hash']}")

    # Output Chain Event Log to JSON file
    out = Path("event_log.json"); out.write_text(json.dumps(chain, indent=2), encoding="utf-8")
    print(f"[OK] Wrote {out}"); verify_chain(json.loads(out.read_text()))
