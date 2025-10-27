# create_test_exe.py - Creates a harmless test executable
import PyInstaller.__main__
import os
from pathlib import Path

# Create a simple harmless Python script
test_script = """
import time
print("This is a harmless test executable running from USB")
print("It will automatically close in 5 seconds...")
time.sleep(5)
print("Test completed successfully!")
"""

# Write the test script to a file
script_path = Path("harmless_test.py")
script_path.write_text(test_script)

# Use PyInstaller to create an executable
PyInstaller.__main__.run([
    'harmless_test.py',
    '--onefile',
    '--console',
    '--name=HarmlessUSBTest',
    '--distpath=.'
])

print("Test executable created in 'dist' folder")