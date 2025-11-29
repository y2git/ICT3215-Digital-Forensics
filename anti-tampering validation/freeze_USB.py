import psutil
import time
import os

def find_main_py_process():
    current_pid = os.getpid()  # avoid freezing this script itself
    matches = []

    for p in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            if p.pid == current_pid:
                continue

            name = (p.info.get("name") or "").lower()
            if "python" not in name:
                continue

            cmdline = p.info.get("cmdline") or []
            for arg in cmdline:
                # only match if the last path component is exactly "main.py"
                if os.path.basename(arg).lower() == "main.py":
                    matches.append(p)
                    break

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return matches


def main():
    print("[*] Looking for python process running main.py...")

    procs = find_main_py_process()

    if not procs:
        print("[!] No python process with main.py found.")
        print("    Make sure U-See Bus is started with something like: python main.py")
        return

    print("[+] Found the following main.py process(es):")
    for p in procs:
        cmd = " ".join(p.info.get("cmdline") or [])
        print(f"    PID {p.pid}   CMD: {cmd}")

    # strictly target the first main.py match
    target = procs[0]
    print(f"\n[+] Suspending PID {target.pid} (main.py)...")
    target.suspend()

    freeze_time = 10
    print(f"[+] Process suspended for {freeze_time} seconds...")
    time.sleep(freeze_time)

    print("[+] Resuming process...")
    target.resume()

    print("[✓] Freeze test complete. If the watchdog is working, U-See Bus should have written a forced digest and exited.")


if __name__ == "__main__":
    main()
