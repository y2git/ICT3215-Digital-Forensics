import psutil, subprocess, time, os, json, threading, ctypes
from pathlib import Path
from watchdog.observers import Observer

from events import EventCollector
from models import ChainEntry
from utils import now_sgt_iso, atomic_write_json
from dataclasses import asdict

import subprocess

def is_usb_devicetype(drive_letter: str):

    try:
        # Query diskdrive info associated with this drive letter
        wmic_cmd = [
            "wmic", "diskdrive", "where",
            "InterfaceType='USB'",
            "get", "Model,MediaType,PNPDeviceID", "/format:list"
        ]
        result = subprocess.run(wmic_cmd, capture_output=True, text=True).stdout

        model = None
        mediatype = None
        pnp = None

        for line in result.splitlines():
            if line.startswith("Model="):
                model = line.split("=", 1)[1].strip().lower()
            elif line.startswith("MediaType="):
                mediatype = line.split("=", 1)[1].strip().lower()
            elif line.startswith("PNPDeviceID="):
                pnp = line.split("=", 1)[1].strip().lower()

        # Must exist
        if not pnp:
            return False
        
        # Must be USB storage
        if "usbstor" not in pnp:
            return False

        # Reject external HDD / SSD
        bad_keywords = [
            "ssd", "solid state", "nvme",
            "portable ssd", "external", "hard disk"
        ]
        if model and any(x in model for x in bad_keywords):
            return False

        # Only allow true removable media
        if mediatype and "removable" not in mediatype:
            return False

        return True

    except Exception:
        return False

def is_removable_storage(path: str):
    try:
        # Windows API: GetDriveTypeW(path)
        # 2 = removable drive
        drive_type = ctypes.windll.kernel32.GetDriveTypeW(path)
        if drive_type == 2:
            return True
        else: 
            return False
    except Exception:
        return False

# Get USB Info (Windows)
def get_usb_device_info(drive_letter: str):
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
    except Exception: 
        pass

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
def create_usb_observer(device, q, observers, chain, last, monitor_usb, stop_event, exec_events):
    # Sometimes Windows takes a second to mount the path
    for _ in range(5):
        if os.path.exists(device):
            break
        time.sleep(1)
    if not os.path.exists(device):
        print(f"[!] Drive {device} not yet ready, skipping observer.")
        return
    
    # Create observer for the USB device if monitoring is enabled
    if monitor_usb:
        obs_usb = Observer()
        obs_usb.schedule(EventCollector(q, "USB"), device, recursive=True)
        obs_usb.start()
        observers[device] = obs_usb  # store by drive letter
        
    print(f"[+] USB device detected and monitored: {device}")

    # Log USB device info
    usb_info = get_usb_device_info(device[:2])
    print(json.dumps(usb_info, indent=2))

    # Add USB info to chain
    chain_entry = ChainEntry.create("usb_inserted", usb_info, last[0])
    chain.append(asdict(chain_entry))
    last[0] = chain_entry.hash
    # Start USB .exe tracking thread
    from monitor import track_exec_from_usb
    track_exec_thread = threading.Thread(target=track_exec_from_usb, args=(device, stop_event, exec_events, chain, last), daemon=True)
    track_exec_thread.start()


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
def start_usb_monitor_thread(q, observers, chain, last, stop_event, exec_events, monitor_usb=True):
    
    # USB insertion/removal callback
    def usb_callback(device, action):
        print(f"[!] Device {device} {action.upper()} at {now_sgt_iso()}") # log the event
        if action == "inserted":
            # Reject non-removable drives (HDD, SSD, NVMe)
            if not is_removable_storage(device):
                print(f"[!] Ignored NON-USB device at {device} (not removable USB thumbdrive or is external storage or is internal storage)")
                usb_info = get_usb_device_info(device[:2])

                # Add USB info to chain
                chain_entry = ChainEntry.create("usb_inserted", usb_info, last[0])
                chain.append(asdict(chain_entry))
                last[0] = chain_entry.hash
                return
            
            if monitor_usb:
                create_usb_observer(device, q, observers, chain, last, monitor_usb, stop_event, exec_events)
        
        elif action == "removed": # remove observer when USB is removed
            remove_usb_observer(device, observers, chain, last)
            
    for p in psutil.disk_partitions(all=False):
        mount = p.device
        wmic_cmd = [
            "wmic", "diskdrive",
            "get", "MediaType"
        ]
        result = subprocess.run(wmic_cmd, capture_output=True, text=True).stdout
        if "Fixed hard disk media" in result:
            continue  # Skip fixed drives
        # Is it a removable USB device at all?
        elif is_removable_storage(mount):
            # Case 1: It *is* a USB thumbdrive
            if is_usb_devicetype(mount[:2]):
                print(f"[!] Existing USB thumbdrive found at startup: {mount}")
        
    #if monitor_usb:
    threading.Thread(target=monitor_usb_insertion, args=(usb_callback,), daemon=True).start() # start monitoring in a separate thread
