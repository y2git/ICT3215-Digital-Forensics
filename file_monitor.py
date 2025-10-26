import time, os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


WATCH = str(Path.home() / "Downloads")  # adjust to any folder

class Handler(FileSystemEventHandler):
    def on_created(self, event):  
        if not event.is_directory: 
            print("created", event.src_path)
    def on_modified(self, event): 
        if not event.is_directory: 
            print("modified", event.src_path)
    def on_deleted(self, event):  
        if not event.is_directory: 
            print("deleted", event.src_path)
    def on_moved(self, event):    
        if not event.is_directory: 
            print("moved", event.src_path, "->", event.dest_path)

print(f"[*] Watching: {WATCH}")
observer = Observer()
observer.schedule(Handler(), WATCH, recursive=True)
observer.start()
try:
    while True: 
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop() 
    observer.join()
