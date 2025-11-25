import os, json, queue, threading,psutil
from pathlib import Path
from watchdog.observers import Observer

from dataclasses import asdict
from typing import List

from events import EventCollector
from usb import start_usb_monitor_thread, get_usb_device_info
from models import ChainEntry, ExecEvent, FileEvent
from utils import now_sgt_iso, now_sgt_str, file_sha256, atomic_write_json
from chain import verify_chain

# We import startup recovery helpers later
from recovery import startup_recovery_check, create_running_marker, remove_running_marker


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
                collector.append(asdict(exeEvent)) # add to collector
                chain_entry = ChainEntry.create("exec_event", asdict(exeEvent), last_ref[0]) # create ChainEntry for exec event
                chain.append(asdict(chain_entry)) # add to chain
                last_ref[0] = chain_entry.hash # update last reference hash
                print(f"[EXEC] From USB: {exe} (PID={pid})") # print exec event
        stop_event.wait(1.0) # wait for 1 second before next check


# Function to write session file
def write_session_file(session_path, file_events, exec_events, chain):
    # Contents of session data (EXACT COMMENT)
    session_data = {
        "timestamp": now_sgt_iso(),
        "file_events": file_events,
        "exec_events": exec_events,
        "chain": chain
    }
    atomic_write_json(session_path, session_data) # write session data to file atomically


# Main function to run the monitor
def run_monitor(local_paths: List[str], usb_mount: str, out_dir: list, monitor_usb = True):
    print("U-See Bus is executed. Press Ctrl+C to stop.")
    base_dir, session_dir, digest_dir = out_dir[0], out_dir[1], out_dir[2]

    Path(base_dir).mkdir(exist_ok=True) # create base output directory
    Path(base_dir+"\\"+session_dir).mkdir(exist_ok=True) # create session output directory
    Path(base_dir+"\\"+digest_dir).mkdir(exist_ok=True) # create digest output directory
    RUN_MARKER = Path(base_dir) / ".running" # path for running marker
    startup_recovery_check(RUN_MARKER, base_dir) # check for unclean shutdown
    create_running_marker(RUN_MARKER) # create running marker

    q = queue.Queue() # initialise queue to hold file events
    chain = [] # initialise list to hold chain entries
    previous_hash = ["0"*64] # initialise previous hash with 64 zeros
    file_events = [] # initialise list to hold file events
    exec_events = [] # initialise list to hold exec events

    chain_entry = ChainEntry.create("tool_start", {"msg":"started"}, previous_hash[0]) # create initial chain entry for U-See Bus starting (tool_start)
    chain.append(asdict(chain_entry))
    previous_hash[0] = chain_entry.hash

    session_path = Path(base_dir +"/"+ session_dir + f"/usb_session_{now_sgt_str()}.json") # path for session file
    write_session_file(session_path, file_events, exec_events, chain) # write initial session file

    observers=[] # list to hold observers

    # For each local path (Downloads, Documents, Desktop), create an observer
    for p in local_paths:
        obs_local=Observer()
        obs_local.schedule(EventCollector(q,"Local"),p,recursive=True)
        obs_local.start()
        observers.append(obs_local)
        print(f"[*] Watching local path: {p}")

    # Start USB observer if enabled
    obs_usb = None
    usb_observers_map = {}  # MUST have map for start_usb_monitor_thread
    start_usb_monitor_thread(q, usb_observers_map, chain, previous_hash, monitor_usb)

    if monitor_usb and os.path.exists(usb_mount):
        obs_usb = Observer()
        obs_usb.schedule(EventCollector(q,"USB"),usb_mount,recursive=True)
        obs_usb.start()
        observers.append(obs_usb)
        print(f"[+] USB device detected and monitored: {usb_mount}")
        
        usb_info=get_usb_device_info(usb_mount[:2])
        print(json.dumps(usb_info,indent=2))

        chain_entry=ChainEntry.create("usb_info", usb_info, previous_hash[0])
        chain.append(asdict(chain_entry))
        previous_hash[0]=chain_entry.hash

    stop_event = threading.Event()
    track_exec_thread = threading.Thread(target=track_exec_from_usb, args=(usb_mount, stop_event, exec_events, chain, previous_hash), daemon=True)
    track_exec_thread.start()

    try:
        while True:
            try:
                event=q.get(timeout=0.5)
                file_events.append(asdict(event))

                chain_entry=ChainEntry.create("file_event",asdict(event),previous_hash[0])
                chain.append(asdict(chain_entry))
                previous_hash[0]=chain_entry.hash
                write_session_file(session_path, file_events, exec_events, chain)
            except queue.Empty:
                pass

    except KeyboardInterrupt:
        print("Stopping monitors...")

        for obs in observers:
            obs.stop()
        for obs in observers:
            obs.join()

        stop_event.set()
        track_exec_thread.join()

        chain_entry = ChainEntry.create("tool_stop", {"msg":"stopped"}, previous_hash[0])
        chain.append(asdict(chain_entry))
        previous_hash[0]=chain_entry.hash
        write_session_file(session_path, file_events, exec_events, chain)

        report={"timestamp":now_sgt_iso(),
                "final_hash":previous_hash[0],
                "file_events":file_events,
                "exec_events": exec_events,
                "chain":chain}

        atomic_write_json(session_path, report)
        print(f"[✓] Report saved: {session_path}")

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
                "files_created": sum(1 for e in file_events if "created" in e["action"]),
                "files_modified": sum(1 for e in file_events if "modified" in e["action"]),
                "files_deleted": sum(1 for e in file_events if "deleted" in e["action"]),
                "files_moved": sum(1 for e in file_events if "moved" in e["action"]),
                "exec_from_usb": len(exec_events)
            }
        }

        digest_name = Path(base_dir)/f"{digest_dir}/final_digest_{now_sgt_str()}.json"
        atomic_write_json(digest_name, digest)
        print(f"[✓] Final digest saved: {digest_name}")

        verify_chain([c for c in chain])
        remove_running_marker(RUN_MARKER)
        print("U-See Bus has stopped successfully.")
