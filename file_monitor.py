import time, os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from pathlib import Path


WATCH = str(Path.home() / "Downloads")  # adjust to any folder

class Handler(FileSystemEventHandler):
    def on_created(self, e):  
        if not e.is_directory: 
            print("created", e.src_path)
    def on_modified(self, e): 
        if not e.is_directory: 
            print("modified", e.src_path)
    def on_deleted(self, e):  
        if not e.is_directory: 
            print("deleted", e.src_path)
    def on_moved(self, e):    
        if not e.is_directory: 
            print("moved", e.src_path, "->", e.dest_path)

print(f"[*] Watching: {WATCH}")
obs = Observer(); obs.schedule(Handler(), WATCH, recursive=True); obs.start()
try:
    while True: time.sleep(1)
except KeyboardInterrupt:
    obs.stop(); obs.join()
