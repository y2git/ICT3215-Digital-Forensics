import psutil, time

# Suspend and resume all python.exe processes
for p in psutil.process_iter(['pid', 'name']):
    
    # Check if the process is python.exe
    if p.info['name'] == 'python.exe':
        # Suspend the process
        p.suspend()
        time.sleep(10) # suspend for 10 seconds
        p.resume() # Resume the process
