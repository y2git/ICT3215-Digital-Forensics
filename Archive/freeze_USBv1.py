import psutil
import time
import os

# Find U-See Bus python process by inspecting command line arguments
def find_useebus_process(): 
    current_pid = os.getpid() # get current script PID to avoid self-matching
    candidates = []

    # Scan all processes
    for p in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # Filter for python processes
            if p.info['name'] and "python" in p.info['name'].lower():
                if p.pid == current_pid:
                    continue  # skip this script itself
                
                # Check for U-See Bus indicators in command line
                cmd = " ".join(p.info.get('cmdline') or [])
                # Look for main.py or U-See or ICT3215 in command line
                if "main.py" in cmd or "U-See" in cmd or "ICT3215" in cmd:
                    candidates.append(p)
        
        # Handle processes that may have terminated or are inaccessible
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue # skip to next process
    # Return list of candidate processes
    return candidates

# Main function to suspend and resume U-See Bus process
def main():
    # Find U-See Bus python processes
    targets = find_useebus_process()
    
    # If none found, inform user and exit
    if not targets:
        print("[!] No U-See Bus python process found.")
        print("    Make sure U-See Bus is running before running this script.")
        return

    # Display found processes
    print("[+] Found the following U-See Bus Python processes:")
    for p in targets:
        print(f"    PID {p.pid}   CMD: {' '.join(p.info.get('cmdline') or [])}")

    # Pick the first candidate (usually the correct one)
    p = targets[0]

    print(f"\n[+] Suspending PID {p.pid}...")
    
    # Suspend the process to simulate freeze
    p.suspend()

    # Keep the process suspended for a duration
    freeze_time = 10  # seconds
    print(f"[+] Process suspended for {freeze_time} seconds...")
    
    # Wait for the freeze duration
    time.sleep(freeze_time)

    # Resume the suspended process
    print("[+] Resuming process...")
    p.resume()
    
    print("[✓] Test complete. U-See Bus should have terminated.")


if __name__ == "__main__":
    main()
