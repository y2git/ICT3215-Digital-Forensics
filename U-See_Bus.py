#imports
import time, psutil

def list_removable_mounts():
    mounts = []
    for part in psutil.disk_partitions(all=False):
        if 'removable' in part.opts:
            mounts.append(part.device)
    return mounts

#When run, print that it started monitoring
print("Started monitoring insertion/removal of USB devices...")

#Initial list of mounts (should be empty if no USB devices are connected)
previous_mounts = set(list_removable_mounts())
while True:
    #detect new mounts
    current_mounts = set(list_removable_mounts())
    
    # Detect newly inserted devices
    inserted_mounts = current_mounts - previous_mounts
    if inserted_mounts:
        print(f"USB device inserted: {list(inserted_mounts)}")
    
    # Detect removed devices
    removed_mounts = previous_mounts - current_mounts
    if removed_mounts:
        print(f"USB device removed: {list(removed_mounts)}")
    
    # Update previous mounts for next iteration
    previous_mounts = current_mounts
    time.sleep(1)