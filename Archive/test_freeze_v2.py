import psutil, time

# Get PID of U-See Bus python.exe from user input
target_pid = int(input("Enter PID of U-See Bus python.exe: "))

# Suspend and resume the specified process
p = psutil.Process(target_pid)
print(f"Suspending PID {target_pid}...") # Suspend the process
p.suspend()

# Keep it suspended for 10 seconds
time.sleep(10)

# Resume the process
print("Resuming...")
p.resume()
