import os, sys, time, json, hashlib, psutil, subprocess, queue, threading, argparse
import datetime as dt
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import signal

# Function to write JSON atomically
def atomic_write_json(path: Path, obj):
    """Safely write JSON to disk and flush to ensure durability."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def write_session_file(session_path, file_events, exec_events, chain):
    session_data = {
        "timestamp": now_sgt_iso(),
        "file_events": file_events,
        "exec_events": exec_events,
        "chain": chain
    }
    atomic_write_json(session_path, session_data)

# Functions to get time
SGT = dt.timezone(dt.timedelta(hours=8))
def now_sgt_iso(): 
    return dt.datetime.now(SGT).isoformat()
def now_sgt_str(): 
    return dt.datetime.now(SGT).strftime("%Y%m%dT%H%M%S")

# Get SHA256 of a file
def file_sha256(path: str) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""): h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

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

# Function to verify the integrity of the chain
def verify_chain(entries: List[Dict]) -> bool:
    previous = "0"*64 # intial previous hash is 64 zeros
    for i, event in enumerate(entries): # iterate through each event in the chain
        payload = f"{event['timestamp_sgt']}|{event['event_type']}|{event['data']}|{event['prev_hash']}".encode() # reconstruct the payload using event
        current_hash = hashlib.sha256(payload).hexdigest() # compute the hash of the payload
        
        # check if the current hash matches the stored hash and if the previous hash matches 
        if current_hash != event["hash"] or event["prev_hash"] != previous:
            print(f"[!] Tamper detected at entry {i}") # print where the tampering is detected, count from 0
            return False
        previous = event["hash"] # update previous hash for next iteration
    print("[✓] Chain verified OK; final digest:", previous) # if no tampering detected, print this
    return True

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
    exe: Optional[str] # the executable path
    cmdline: List[str] # the command line arguments
    username: Optional[str] # the username of the process owner

# Get USB Info (Windows)
def get_usb_device_info(drive_letter: str) -> Dict[str, Optional[str]]:
    info = {"mount": drive_letter, "volume_label": None, "serial_number": None, "pnp_id": None} # default info
    try:
        # Get volume label and serial number
        r = subprocess.run(["wmic","volume","where",f"DriveLetter='{drive_letter}'","get","Label,SerialNumber","/format:list"], capture_output=True,text=True)
        
        # Split output into lines and extract relevant info
        for line in r.stdout.splitlines():
            if "Label=" in line: 
                info["volume_label"] = line.split("=",1)[1].strip()
            if "SerialNumber=" in line: 
                info["serial_number"] = line.split("=",1)[1].strip()
    except Exception: pass
    try:
        # Get PNPDeviceID
        r = subprocess.run(["wmic","diskdrive","where","MediaType='Removable Media'","get","PNPDeviceID","/format:list"], capture_output=True,text=True)
        for line in r.stdout.splitlines():
            if "PNPDeviceID=" in line:
                info["pnp_id"] = line.split("=",1)[1].strip()
                break
    except Exception:
        pass
    return info

last_seen_hashes = {} # initialize last seen hashes dictionary
recent_deleted = {} # initialize recent deleted files dictionary
# Class to record file system events
class EventCollector(FileSystemEventHandler):
    def __init__(self, q, label="Local"): 
        super().__init__()
        self.q = q
        self.label = label
    def on_created(self, e):
        if not e.is_directory:
            # Check for move: same filename deleted moments ago
            basename = os.path.basename(e.src_path)

            for old_path, t in list(recent_deleted.items()):
                if os.path.basename(old_path) == basename:
                    # If deleted within last 1 sec → likely a move
                    if time.time() - t < 1.0:
                        # Remove from delete cache
                        recent_deleted.pop(old_path, None)

                        event = FileEvent(now_sgt_iso(), "moved", old_path, e.src_path, file_sha256(e.src_path), self.label)
                        self.q.put(event)
                        print(f"[→] {self.label}: {old_path} moved to {e.src_path}")
                        return
            h = file_sha256(e.src_path) # get the sha256 hash of created file
            last_seen_hashes[e.src_path] = h # store the hash in last seen hashes
            event = FileEvent(now_sgt_iso(), "created", e.src_path, None, h, self.label) # create a FileEvent for creation
            self.q.put(event) # put the event in the queue
            print(f"[+] {self.label}: {e.src_path} created") # print creation event
    def on_modified(self, e):
        if not e.is_directory:
            h = file_sha256(e.src_path) # get the sha256 hash of modified file
            previous_hash = last_seen_hashes.get(e.src_path) # get the previous hash
            
            # determine the action based on hash comparison
            if h is None: # if hash is None, file is unreadable
                action ="modified (unreadable)"
            elif previous_hash == h: # if hash is unchanged
                action = "metadata modified, content unchanged"
            else: # if hash has changed
                action = "file content modified"
            
            last_seen_hashes[e.src_path] = h # update the last seen hash
            event = FileEvent(now_sgt_iso(), action, e.src_path, None, h, self.label) # create a FileEvent for modification
            self.q.put(event) # put the event in the queue
            print(f"[*] {self.label}: {e.src_path} {action}") # print modification event
    def on_deleted(self, e):
        if not e.is_directory:
            recent_deleted[e.src_path] = time.time() # record the deletion time
            last_seen_hashes.pop(e.src_path, None) # remove the file from last seen hashes
            event=FileEvent(now_sgt_iso(), "deleted", e.src_path, None, None, self.label) # create a FileEvent for deletion
            self.q.put(event) # put the event in the queue
            print(f"[-] {self.label}: {e.src_path} deleted") # print deletion event
    def on_moved(self, e):
        if not e.is_directory:
            h = file_sha256(getattr(e, "dest_path", e.src_path)) # get the sha256 hash of moved file
            last_seen_hashes.pop(e.src_path, None) # remove the source path from last seen hashes
            last_seen_hashes[getattr(e, "dest_path", e.src_path)] = h # update the destination path in last seen hashes
            event = FileEvent(now_sgt_iso(), "moved", e.src_path, getattr(e, "dest_path", None), h, self.label) # create a FileEvent for move
            self.q.put(event) # put the event in the queue
            print(f"[→] {self.label}: {e.src_path} moved to {e.dest_path}") # print move event



# ----------------------------
# USB Monitoring
# ----------------------------

# Monitor USB insertion/removal (Windows)
def monitor_usb_insertion(callback):
    prev_drives = {p.device for p in psutil.disk_partitions(all=False)} # get initial set of drives
    # Polling loop
    while True:
        time.sleep(2)
        current_drives = {p.device for p in psutil.disk_partitions(all=False)} # get current set of drives
        new_drives = current_drives - prev_drives # detect new drives
        removed_drives = prev_drives - current_drives # detect removed drives
        
        # Trigger callbacks for changes
        for d in new_drives: # new drive detected
            callback(d, "inserted")
        for d in removed_drives: # drive removed
            callback(d, "removed")

        prev_drives = current_drives # update previous drives for next iteration

# Create USB observer
def create_usb_observer(device, q, observers, chain, last):
    # Sometimes Windows takes a second to mount the path
    for _ in range(5):
        if os.path.exists(device):
            break
        time.sleep(1)
    if not os.path.exists(device):
        print(f"[!] Drive {device} not yet ready, skipping observer.")
        return
    
    # Create observer for the USB device
    obs_usb = Observer()
    obs_usb.schedule(EventCollector(q, "USB"), device, recursive=True)
    obs_usb.start()
    print(f"[+] USB device detected and monitored: {device}")
    observers[device] = obs_usb  # store by drive letter

    # Log USB device info
    usb_info = get_usb_device_info(device[:2])
    print(json.dumps(usb_info, indent=2))

    # Add USB info to chain
    chain_entry = ChainEntry.create("usb_inserted", usb_info, last[0])
    chain.append(asdict(chain_entry))
    last[0] = chain_entry.hash

# Remove USB observer
def remove_usb_observer(device, observers, chain, last):
    obs_usb = observers.pop(device, None) # get and remove observer
    if obs_usb: # if observer exists
        obs_usb.stop() # stop the observer
        obs_usb.join(timeout=3) # wait for it to finish
        print(f"[-] USB device removed: {device}")
        # Log chain entry for USB REMOVAL
        removal_data = {"mount": device, "timestamp": now_sgt_iso()}
        chain_entry = ChainEntry.create("usb_removed", removal_data, last[0])
        chain.append(asdict(chain_entry))
        last[0] = chain_entry.hash

# Start USB monitor thread
def start_usb_monitor_thread(q, observers, chain, last, monitor_usb):
    if not monitor_usb:
        return  # USB monitoring disabled

    # USB insertion/removal callback
    def usb_callback(device, action):
        print(f"[USB] Device {device} {action.upper()} at {now_sgt_iso()}") # log the event
        if action == "inserted": # create observer when USB is inserted
            create_usb_observer(device, q, observers, chain, last)
        elif action == "removed": # remove observer when USB is removed
            remove_usb_observer(device, observers, chain, last)

    threading.Thread(target=monitor_usb_insertion, args=(usb_callback,), daemon=True).start() # start monitoring in a separate thread

# .exe monitoring from USB
def track_exec_from_usb(mount: str, stop_event: threading.Event, collector: List[ExecEvent], chain: List[ChainEntry], last_ref: List[str]):
    seen=set() # set to track seen PIDs
    while not stop_event.is_set(): # loop until stop event is set
        # Check all processes
        for p in psutil.process_iter(attrs=["pid","exe","cmdline","username"]):
            pid = p.info["pid"] # get the process id
            
            # skip if already seen
            if pid in seen:
                continue

            seen.add(pid) # mark pid as seen
            exe = p.info.get("exe") # get the executable path

            # check if exe is from the USB mount
            if exe and exe.lower().startswith(mount.lower()):
                exeEvent=ExecEvent(now_sgt_iso(),pid,exe,p.info.get("cmdline") or [],p.info.get("username")) # create ExecEvent
                collector.append(exeEvent) # add to collector
                chain_entry = ChainEntry.create("exec_event", asdict(exeEvent), last_ref[0]) # create ChainEntry for exec event
                chain.append(asdict(chain_entry)) # add to chain
                last_ref[0] = chain_entry.hash # update last reference hash
                print(f"[EXEC] From USB: {exe} (PID={pid})") # print exec event
        stop_event.wait(1.0) # wait for 1 second before next check

# ----------------------------
# Main logic
# ----------------------------

# Main function to run the monitor
def run_monitor(local_paths: List[str], usb_mount: str, out_dir: list, monitor_usb = True):
    print("U-See Bus is executed. Press Ctrl+C to stop.")
    base_dir, session_dir, digest_dir = out_dir[0], out_dir[1], out_dir[2]

    Path(base_dir).mkdir(exist_ok=True) # create base output directory
    Path(base_dir+"\\"+session_dir).mkdir(exist_ok=True) # create session output directory
    Path(base_dir+"\\"+digest_dir).mkdir(exist_ok=True) # create digest output directory
    RUN_MARKER = Path(base_dir) / ".running"
    #CHECKPOINT_DIR = Path(base_dir) / "checkpoints"
    #print(type(RUN_MARKER))
    startup_recovery_check(RUN_MARKER, base_dir)
    create_running_marker(RUN_MARKER)
    q = queue.Queue() # initialise queue to hold file events
    chain = [] # initialise list to hold chain entries
    previous_hash = ["0"*64] # initialise previous hash with 64 zeros
    file_events = [] # initialise list to hold file events
    exec_events = [] # initialise list to hold exec events
    chain_entry = ChainEntry.create("tool_start", {"msg":"started"}, previous_hash[0]) # create initial chain entry for U-See Bus starting (tool_start)
    chain.append(asdict(chain_entry)) # add to chain
    previous_hash[0] = chain_entry.hash # update previous hash

    session_path = Path(base_dir +"/"+ session_dir + f"/usb_session_{now_sgt_str()}.json")
    write_session_file(session_path, file_events, exec_events, chain)

    observers=[] # list to hold observers

    # For each local path (Downloads, Documents, Desktop), create an observer
    for p in local_paths:
        # Start local observers
        obs_local=Observer()
        obs_local.schedule(EventCollector(q,"Local"),p,recursive=True)
        obs_local.start()

        observers.append(obs_local) # add to observers list
        print(f"[*] Watching local path: {p}")

    # Start USB observer if enabled
    obs_usb = None
    start_usb_monitor_thread(q, {}, chain, previous_hash, monitor_usb)
    
    # If USB monitoring is enabled and the USB mount exists
    if monitor_usb and os.path.exists(usb_mount):
        # Create an observer for USB
        obs_usb = Observer()
        obs_usb.schedule(EventCollector(q,"USB"),usb_mount,recursive=True)
        obs_usb.start()

        observers.append(obs_usb) # add to observers list
        print(f"[+] USB device detected and monitored: {usb_mount}") # log USB monitoring
        
        usb_info=get_usb_device_info(usb_mount[:2]) # get USB device info
        print(json.dumps(usb_info,indent=2)) # print USB info

        chain_entry=ChainEntry.create("usb_info", usb_info, previous_hash[0]) # create chain entry for USB info
        chain.append(asdict(chain_entry)) # add to chain
        previous_hash[0]=chain_entry.hash

    stop_event = threading.Event() # event to signal stopping of exec tracking
    # Start thread to track .exe executions from USB
    track_exec_thread = threading.Thread(target=track_exec_from_usb, args=(usb_mount, stop_event, exec_events, chain, previous_hash), daemon=True)
    track_exec_thread.start()

    try:
        while True:
            try:
                event=q.get(timeout=0.5) # get event from queue with timeout
                file_events.append(event) # add to file events list

                # Create chain entry for file event
                chain_entry=ChainEntry.create("file_event",asdict(event),previous_hash[0]) # create chain entry
                chain.append(asdict(chain_entry)) # add to chain
                previous_hash[0]=chain_entry.hash # update previous hash
                write_session_file(session_path, file_events, exec_events, chain)
            except queue.Empty:
                pass
    # When Ctrl+C to stop monitoring
    except KeyboardInterrupt:

        print("Stopping monitors...")

        # Stop all observers
        for obs in observers:
            obs.stop()
        obs.join() # wait for observer to finish
        
        # Stop exec tracking thread
        stop_event.set() # signal exec tracking thread to stop
        track_exec_thread.join() # wait for exec tracking thread to finish
        
        # Final chain entry for tool stop
        chain_entry = ChainEntry.create("tool_stop", {"msg":"stopped"}, previous_hash[0]) # create chain entry for U-See Bus stopping (tool_stop)
        chain.append(asdict(chain_entry)) # add to chain
        previous_hash[0]=chain_entry.hash # update previous hash
        write_session_file(session_path, file_events, exec_events, chain)
        # Save report
        report={"timestamp":now_sgt_iso(),
                "final_hash":previous_hash[0],
                "file_events":[asdict(e) for e in file_events],
                "exec_events":[asdict(e) for e in exec_events],
                "chain":chain}
        
        # Save session report
        #session_path = Path(base_dir)/f"{session_dir}/usb_session_{now_sgt_str()}.json"
        atomic_write_json(session_path, report)
        print(f"[✓] Report saved: {session_path}")

        # Save final digest
        digest = {
            "tool": "U-See_Bus",
            "version": "1.0",
            "timestamp": now_sgt_iso(),
            "session_path": str(session_path),
            "session_sha256": file_sha256(session_path),
            "final_chain_hash": previous_hash[0],
            "total_events": len(chain),
            "first_event": file_events[0].timestamp_sgt if file_events else None,
            "last_event": file_events[-1].timestamp_sgt if file_events else None,
            "summary": {
                "files_created": sum(1 for e in file_events if "created" in e.action),
                "files_modified": sum(1 for e in file_events if "modified" in e.action),
                "files_deleted": sum(1 for e in file_events if "deleted" in e.action),
                "exec_from_usb": len(exec_events)
            }
        }     
        # Save digest to file  
        digest_name = Path(base_dir)/f"{digest_dir}/final_digest_{now_sgt_str()}.json"
        atomic_write_json(digest_name, digest)
        print(f"[✓] Final digest saved: {digest_name}")

        verify_chain([c for c in chain]) # verify the chain before exiting
        remove_running_marker(RUN_MARKER)
        print("U-See Bus has stopped successfully.")

# Checking if script ended unexpectedly

def create_running_marker(run_marker: Path):
    run_marker.parent.mkdir(parents=True, exist_ok=True)
    with open(run_marker, "w") as f:
        f.write("running\n")
        f.flush()
        os.fsync(f.fileno())

def remove_running_marker(run_marker: Path):
    try:
        run_marker.unlink()
    except FileNotFoundError:
        pass

def write_checkpoint(checkpoint_dir: Path, final_chain_hash: str, session_path: Path):
    checkpoint_dir.mkdir(parents=True, exist_ok=True)
    cp = {
        "timestamp": now_sgt_iso(),
        "final_chain_hash": final_chain_hash,
        "session_path": str(session_path)
    }
    fname = checkpoint_dir / f"checkpoint_{now_sgt_str()}.json"
    with open(fname, "w") as f:
        json.dump(cp, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def startup_recovery_check(run_marker: Path, base_dir: Path):
    if run_marker.exists():
        print("[!] Unclean shutdown detected: .running marker found.")
        #print(run_marker)
        sessions_path = Path(base_dir + "/usb-sessions")
        sessions_path.mkdir(parents=True, exist_ok=True)

        sessions = sorted(sessions_path.glob("usb_session_*.json"))
        if sessions:
            last_session = sessions[-1]

            digest_dir = Path(base_dir + "/final-digest")
            digest_dir.mkdir(parents=True, exist_ok=True)

            digest_path = digest_dir / f"final_digest_unclean_{now_sgt_str()}.json"

            digest_obj = {
                "tool": "U-See_Bus",
                "timestamp": now_sgt_iso(),
                "session_path": str(last_session),
                "session_sha256": file_sha256(last_session),
                "note": "unclean_shutdown_detected_before_startup"
            }

            atomic_write_json(digest_path, digest_obj)
            print(f"[!] Created recovery digest: {digest_path}")
        else:
            print("[!] Warning: No session files found. Nothing to recover.")

        # Remove marker to allow clean start
        try:
            run_marker.unlink()
        except:
            pass


# ----------------------------
# CLI entry point
# ----------------------------
if __name__=="__main__":
    parser=argparse.ArgumentParser(description="USB Activity Correlator (Demonstration Enhanced)")
    parser.add_argument("--paths",nargs="*",help="Extra directories to monitor. Usage: python U-See_Bus.py --paths 'C:\path1' 'D:\path2' ",default=[]) # usage: python U-See_Bus.py -- --paths "C:\path1" "D:\path2"
    parser.add_argument("--no-usb-monitor",action="store_true",help="Disable USB monitoring")
    parser.add_argument("--verify",help="Verify integrity of a saved JSON report. Usage: python U-See_Bus.py --verify /path/to/usb_session_<timestamp>.json or /path/to/final_digest_<timestamp>.json")
    parser.add_argument("--outdir",default=["usb-reports", "usb-sessions", "final-digest"],help="Output directory for reports. Usage: python U-See_Bus.py --outdir '<base_dir>' '<session_dir>' '<digest_dir>'", nargs=3)
    parser.add_argument("--usb-mount",default="D:\\",help="Drive letter for USB (Windows default: D:\\). Usage: python U-See_Bus.py --usb-mount '<Letter i.e E>:\\'")
    args=parser.parse_args()

    if args.verify:
        data = json.loads(Path(args.verify).read_text()) # load the JSON selected for verification
        
        # if it is session JSON
        if isinstance(data, dict) and "chain" in data:
            verify_chain(data["chain"])  # verify only the chain list
            sys.exit(0)

        # if it is final digest JSON
        if isinstance(data, dict) and "session_path" in data and "session_sha256" in data: # Check for required keys
            session_path = Path(data["session_path"]) # get the session path from digest
            if not session_path.exists(): # check if session file exists
                print(f"[!] Session file not found: {session_path}")
                sys.exit(1)
            expected_hash = file_sha256(session_path) # compute the sha256 of the session file
            print(f"[*] Checking session hash for {session_path.name}")
            print(f"    expected: {expected_hash}")
            print(f"    actual:   {data['session_sha256']}")

            if expected_hash != data["session_sha256"]: # compare expected and actual hash
                print("[!] Session file hash mismatch — possible tampering!") # print message if hashes are different
                sys.exit(1)

            # Load session JSON and verify the chain
            session_data = json.loads(session_path.read_text(encoding="utf-8"))
            if "chain" not in session_data: # check if chain exists in session data
                print("[!] Session file has no 'chain' array. Either wrong file, or tampering has occurred to remove chain.") # print message if chain is missing
                sys.exit(1)

            verify_chain(session_data["chain"]) # verify the chain integrity
            expected_recomputed_final = session_data["chain"][-1]["hash"] # get the final hash from the chain

            print(f"[*] Expected final_chain_hash: {expected_recomputed_final}") # print expected final chain hash
            print(f"[*] Current chain end hash:    {data['final_chain_hash']}") # print current chain end hash from digest

            # Compare the recomputed final hash with the one in the digest
            if expected_recomputed_final != data["final_chain_hash"]:
                print("[!] Chain hash mismatch — session altered after digest creation!")
                sys.exit(1)

            # If all checks pass
            print("[✓] Final digest verification succeeded. Session integrity intact.")
            sys.exit(0)


    # Prepare local paths to monitor
    HOME=str(Path.home())
    local_paths=[os.path.join(HOME,d) for d in ["Downloads","Documents","OneDrive\\Desktop"] if os.path.isdir(os.path.join(HOME,d))]
    local_paths.extend(args.paths)

    run_monitor(local_paths,args.usb_mount,args.outdir,monitor_usb=not args.no_usb_monitor)
