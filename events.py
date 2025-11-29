import os, time
from watchdog.events import FileSystemEventHandler
from dataclasses import asdict
from typing import List, Dict, Optional

# Import shared utilities and models
from utils import file_sha256, now_sgt_iso
from models import FileEvent

# These globals are EXACTLY as in the original script
last_seen_hashes = {} # initialize last seen hashes dictionary
recent_deleted = {} # initialize recent deleted files dictionary

# Thread lock for shared dictionaries (added for safety but logic unchanged)
import threading
dict_lock = threading.Lock()

# Class to record file system events
class EventCollector(FileSystemEventHandler):
    def __init__(self, q, label="Local"): 
        super().__init__()
        self.q = q
        self.label = label

    def on_created(self, e):
        if e.is_directory:
            event = FileEvent(now_sgt_iso(), "directory_created", e.src_path, None, None, self.label)
            self.q.put(event)
            print(f"[+] {self.label}: Directory created → {e.src_path}")
            return
        if not e.is_directory:
            # Check for move: same filename deleted moments ago
            basename = os.path.basename(e.src_path)

            # ORIGINAL LOGIC, wrapped with lock for safety
            with dict_lock:
                for old_path, t in list(recent_deleted.items()):
                    if os.path.basename(old_path) == basename:
                        # If deleted within last 1 sec → likely a move
                        if time.time() - t < 1.0:
                            # Remove from delete cache
                            recent_deleted.pop(old_path, None)
                            # Replace created event with moved event
                            event = FileEvent(now_sgt_iso(), "moved", old_path, e.src_path, file_sha256(e.src_path), self.label)
                            self.q.put(event)
                            print(f"[→] {self.label}: {old_path} moved to {e.src_path}")
                            return

            h = file_sha256(e.src_path) # get the sha256 hash of created file

            with dict_lock:
                last_seen_hashes[e.src_path] = h # store the hash in last seen hashes

            event = FileEvent(now_sgt_iso(), "created", e.src_path, None, h, self.label) # create a FileEvent for creation
            self.q.put(event) # put the event in the queue
            print(f"[+] {self.label}: {e.src_path} created") # print creation event

    def on_modified(self, e):
        if not e.is_directory:
            h = file_sha256(e.src_path) # get the sha256 hash of modified file

            with dict_lock:
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
        if e.is_directory:
            event = FileEvent(now_sgt_iso(), "directory_deleted", e.src_path, None, None, self.label)
            self.q.put(event)
            print(f"[-] {self.label}: Directory deleted → {e.src_path}")
            return
        if not e.is_directory:
            with dict_lock:
                recent_deleted[e.src_path] = time.time() # record the deletion time
                last_seen_hashes.pop(e.src_path, None) # remove the file from last seen hashes

            event = FileEvent(now_sgt_iso(), "deleted", e.src_path, None, None, self.label) # create a FileEvent for deletion
            self.q.put(event) # put the event in the queue
            print(f"[-] {self.label}: {e.src_path} deleted") # print deletion event

    def on_moved(self, e):
        if e.is_directory:
            event = FileEvent(now_sgt_iso(), "directory_moved", e.src_path, e.dest_path, None, self.label)
            self.q.put(event)
            print(f"[→] {self.label}: Directory moved {e.src_path} → {e.dest_path}")
            return

        if not e.is_directory:
            dest = getattr(e, "dest_path", e.src_path)
            h = file_sha256(dest) # get the sha256 hash of moved file

            with dict_lock:
                last_seen_hashes.pop(e.src_path, None) # remove the source path from last seen hashes
                last_seen_hashes[dest] = h # update the destination path in last seen hashes

            event = FileEvent(now_sgt_iso(), "moved", e.src_path, dest, h, self.label) # create a FileEvent for move
            self.q.put(event) # put the event in the queue
            print(f"[→] {self.label}: {e.src_path} moved to {e.dest_path}") # print move event
