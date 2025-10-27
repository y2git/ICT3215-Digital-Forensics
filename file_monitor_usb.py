import time, psutil

USB_MOUNT = "D:\\"  # change to your USB letter

seen = set()
print(f"[*] Watching for processes started from {USB_MOUNT} ... Ctrl+C to stop")
try:
    while True:
        for p in psutil.process_iter(attrs=["pid","exe","cmdline"]):
            pid = p.info["pid"]
            if pid in seen: continue
            seen.add(pid)
            exe = p.info.get("exe")
            if exe and exe.lower().startswith(USB_MOUNT.lower()):
                print(f"[EXEC] PID={pid} EXE={exe} CMD={p.info.get('cmdline')}")
        time.sleep(1)
except KeyboardInterrupt:
    pass