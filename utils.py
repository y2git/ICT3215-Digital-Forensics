import os, json, hashlib
import datetime as dt
from pathlib import Path
import tempfile

# Functions to get time
SGT = dt.timezone(dt.timedelta(hours=8))

def now_sgt_iso(): 
    return dt.datetime.now(SGT).isoformat()

def now_sgt_str(): 
    return dt.datetime.now(SGT).strftime("%Y%m%dT%H%M%S")

# Get SHA256 of a file
def file_sha256(path: str):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# Function to write JSON atomically
def atomic_write_json(path: Path, obj):
    path.parent.mkdir(parents=True, exist_ok=True) # ensure directory exists

    # More robust atomic write using temp file
    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", dir=path.parent) as tmp:
        json.dump(obj, tmp, indent=2) # write JSON data
        tmp.flush()
        os.fsync(tmp.fileno())
        temp_name = tmp.name

    os.replace(temp_name, path)
