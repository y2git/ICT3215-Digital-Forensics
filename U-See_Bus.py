#imports
import time, psutil, json
import datetime as dt
from pathlib import Path

SGT = dt.timezone(dt.timedelta(hours=8))
def now_sgt_iso(): 
    return dt.datetime.now(SGT).isoformat()

def list_removable_mounts():
    return [part.device for part in psutil.disk_partitions(all=False) if 'removable' in part.opts]

events, out = [], Path("usb_events.json")

#When run, print that it started monitoring
print("Started monitoring insertion/removal of USB device")

#Initial list of mounts (should be empty if no USB devices are connected)
previous_mounts = set(list_removable_mounts())
while True:
    #detect new mounts
    current_mounts = set(list_removable_mounts())
    
    # Detect newly inserted devices
    inserted_mounts, removed_mounts = current_mounts - previous_mounts, previous_mounts - current_mounts
    if inserted_mounts:
            event = {"timestamp_sgt": now_sgt_iso(), "event": "usb_insert", "mount": list(inserted_mounts)[0]}
            events.append(event); 
            print(event)

    if removed_mounts:
         event = {"timestamp_sgt": now_sgt_iso(), "event": "usb_remove", "mount": list(removed_mounts)[0]}
         events.append(event); 
         print(event)
         out.write_text(json.dumps(events, indent=2), encoding="utf-8")
         print(f"Wrote {out}")
    previous_mounts = current_mounts
    time.sleep(1)
    
    # Detect removed devices
    removed_mounts = previous_mounts - current_mounts
    if removed_mounts:
        print(f"USB device removed: {list(removed_mounts)}")
    
    # Update previous mounts for next iteration
    previous_mounts = current_mounts
    time.sleep(1)