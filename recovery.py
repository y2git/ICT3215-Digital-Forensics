import os
from pathlib import Path
from utils import now_sgt_iso, now_sgt_str, file_sha256, atomic_write_json

# Function to create .running marker to indicate script is running
def create_running_marker(run_marker: Path):
    run_marker.parent.mkdir(parents=True, exist_ok=True)
    with open(run_marker, "w") as f:
        f.write("running\n")
        f.flush()
        os.fsync(f.fileno())

# Function to remove .running marker on clean exit
def remove_running_marker(run_marker: Path):
    try:
        run_marker.unlink()
    except FileNotFoundError:
        pass

# Checking if script ended unexpectedly last time
def startup_recovery_check(run_marker: Path, base_dir: Path):
    if run_marker.exists(): # if .running marker exists
        print("[!] Unclean shutdown detected: .running marker found.")
        sessions_path = Path(base_dir + "/usb-sessions")
        sessions_path.mkdir(parents=True, exist_ok=True)

        sessions = sorted(sessions_path.glob("usb_session_*.json"))
        if sessions:
            last_session = sessions[-1]

            digest_dir = Path(base_dir + "/final-digest")
            digest_dir.mkdir(parents=True, exist_ok=True)

            digest_path = digest_dir / f"final_digest_unclean_{now_sgt_str()}.json"

            digest_obj = {
                "tool": "U-See_Bus",
                "timestamp": now_sgt_iso(),
                "session_path": str(last_session),
                "session_sha256": file_sha256(last_session),
                "note": "unclean_shutdown_detected_before_startup"
            }

            atomic_write_json(digest_path, digest_obj)
            print(f"[!] Created recovery digest: {digest_path}")
        else:
            print("[!] Warning: No session files found. Nothing to recover.")

        # Remove marker to allow clean start
        try:
            run_marker.unlink()
        except:
            pass
