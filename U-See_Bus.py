#imports
import time, psutil, json
import datetime as dt
from pathlib import Path

# Set Singapore Timezone
SGT = dt.timezone(dt.timedelta(hours=8))
# Get Current time in SGT
def now_sgt_iso(): 
    return dt.datetime.now(SGT).isoformat()
# List removable mounts
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
        print(f"USB device inserted: {list(inserted_mounts)}")
        events.append(event); 
        print(event)

    # Detect removed devices
    if removed_mounts:
        event = {"timestamp_sgt": now_sgt_iso(), "event": "usb_remove", "mount": list(removed_mounts)[0]}
        events.append(event); 
        print(event)
        out.write_text(json.dumps(events, indent=2), encoding="utf-8")
        print(f"Wrote {out}")
        print(f"USB device removed: {list(removed_mounts)}")
    
    # Update previous mounts for next iteration
    previous_mounts = current_mounts
    time.sleep(1)