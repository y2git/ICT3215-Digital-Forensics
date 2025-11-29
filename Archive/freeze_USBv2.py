import psutil
import time
import os

def find_main_process():
    # Scan all processes to find one running main.py
    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            # Check command line for main.py
            cmd = p.info.get("cmdline") or []
            if any("main.py" in arg.lower() for arg in cmd):
                return p
        # Handle processes that may have terminated or are inaccessible    
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return None

# Main function to suspend and resume U-See Bus main.py process
def main():
    # Wait for U-See Bus main.py process to start
    print("[*] Waiting for U-See Bus (main.py) to start...")

    target = None
    # Wait until the main.py process is found
    while target is None:
        target = find_main_process()
        time.sleep(0.5)

    # Display found process
    print(f"[+] Found U-See Bus main process: PID {target.pid}")
    print(f"    CMD: {' '.join(target.info.get('cmdline') or [])}")

    # Give some time before suspending
    time.sleep(1)

    # Suspend the process to simulate freeze
    print(f"[+] Suspending PID {target.pid}...")
    target.suspend()

    # Keep the process suspended for a duration
    freeze_time = 10 # seconds
    print(f"[+] Process suspended for {freeze_time} seconds...")
    time.sleep(freeze_time)

    print("[+] Resuming process...")
    target.resume()

    print("[✓] Freeze test completed. U-See Bus should have terminated.")


if __name__ == "__main__":
    main()
