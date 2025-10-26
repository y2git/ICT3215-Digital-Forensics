import time, hashlib, queue, os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path

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

# Folder to monitor for file changes
FOLDER_OBSERVED = str(Path.home() / "Downloads")  # adjust to any folder

# Handler to detect changes to observed folder
class Handler(FileSystemEventHandler):
    # Handle file creation event
    def on_created(self, e):
        if e.is_directory: return
        print("created", e.src_path, "SHA256=", file_sha256(e.src_path))
    # Handle file modification event
    def on_modified(self, e):
        if e.is_directory: return
        print("modified", e.src_path, "SHA256=", file_sha256(e.src_path))
    # Handle file deletion event
    def on_deleted(self, event):  
        if not event.is_directory: 
            print("deleted", event.src_path)
    # Handle file movement event
    def on_moved(self, event):    
        if not event.is_directory: 
            print("moved", event.src_path, "->", event.dest_path)

# Print the folder being observed
print(f"Observing: {FOLDER_OBSERVED}")

# Create observer and schedule handler
observer = Observer()
observer.schedule(Handler(), FOLDER_OBSERVED, recursive=True)
observer.start()
try:
    while True: 
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop() 
    observer.join()
