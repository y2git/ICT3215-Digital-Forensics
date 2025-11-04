# ICT3215-Digital-Forensics-GonezCase

U-See Bus is a Python script that is used to detect the insertion and removal of USB thumbdrives and to detect changes made to files within the folders it is monitoring (Downloads, Documents and Desktop by default). 
It also logs any .exe files run by USB drives and uses cryptographic chains to ensure forensic integrity

---

## Table of Contents

- [System Overview]
- [Features]
- [System Architecture]
- [Dependencies]
- [Installation]
- [Usage]
- [Output]
- [Verification]
- [Limitations]

## System Overview

U-See Bus provides real-time monitoring of file events when USB drives are connected into a Windows computer.
The tool generates 2 files that are used to verify the integrity of the logs.
1. A session log of the file events that occurred
2. A final digest that uses hashes to verify the integrity of the log
When the files are used with U-See Bus, the user will be able to tell if either of them have been tampered with, ensuring chain-of-custody validation

##

Features

1. Records USB insertions and removal
2. Monitor selected folders (Downloads, Documents and Desktop by default)
3. Track file activity like file creation, deletion, modification and moving
4. Detects if a .exe is executed from a USB drive
5. Generates a log file that uses SHA256 chain hashes
6. Generates a final digest file that can detect tampering
7. Additional arguments available such as to change location of USB sessions and final digest files, disable USB monitoring (since you cannot safely eject USB otherwise), change the USB drive name (default is D:\ for Windows)

## System Architecture
<INSERT LATER>

## Dependencies
All dependencies are listed in `requirements.txt`.

To install them, follow the setup steps in the Installation section.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/y2git/ICT3215-Digital-Forensics
cd ICT3215-Digital-Forensics-GonezCase

# 2. Create a virtual environment
# On macOS / Linux:
python3 -m venv .venv
# On Windows:
python -m venv .venv

# 3. Activate the virtual environment
# On macOS / Linux:
source .venv/bin/activate
# On Windows:
.venv\Scripts\activate 


# 4. Install dependencies
pip install -r requirements.txt
```

---

## Usage

Default monitoring
```bash
python U-See_Bus.py
```

Specify folders to monitor
```bash
python U-See_Bus.py --paths "C:\Users\<User>\Desktop" "C:\Evidence"
```

Disable USB monitoring
```bash
python U-See_Bus.py --no-usb-monitor
```

Custom output directories
```bash
python U-See_Bus.py --outdir <directory 1> <directory 2> <directory 3>
```

Verify an existing session or digest
```bash
python U-See_Bus.py --verify path/to/usb_session_<timestamp>.json
```
```bash
python U-See_Bus.py --verify path/to/final_digest_<timestamp>.json
```