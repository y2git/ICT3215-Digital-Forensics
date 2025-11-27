# ICT3215-Digital-Forensics-GonezCase

U-See Bus is a Python script that is used to detect the insertion and removal of USB thumbdrives and to detect changes made to files within the folders it is monitoring (Downloads, Documents and Desktop by default).  
It also logs any `.exe` files run by USB drives and uses cryptographic chains to ensure forensic integrity.

---

# U-See Bus – USB Forensic Activity Monitor

A lightweight digital forensics tool for Windows that monitors USB activity, tracks file changes, detects executables launched from removable drives, and generates tamper-evident logs using cryptographic hash chaining.

---

## Table of Contents

- [System Overview](#system-overview)
- [Features](#features)
- [System Architecture](#system-architecture)
- [Dependencies](#dependencies)
- [Installation](#installation)
- [Usage](#usage)
- [Output](#output)
- [Verification](#verification)
- [Limitations](#limitations)

---

## System Overview

U-See Bus provides real-time monitoring of file events when USB drives are connected into a Windows computer.

The tool generates **two forensic artifacts**:

1. **Session Log** — a full record of all file, USB, and process events  
2. **Final Digest** — a summary document containing session hash + final chain hash  

Both artifacts are cryptographically linked using SHA-256 chain hashing.  
This ensures any alteration becomes detectable, supporting secure chain-of-custody validation.

---

## Features

1. Records USB insertions and removals  
2. Monitors selected folders (Downloads, Documents, Desktop by default)  
3. Tracks file events: create, delete, modify, move  
4. Detects `.exe` execution when launched from USB  
5. Builds an immutable hash-chain for every event  
6. Produces a final digest summarizing chain integrity  
7. Supports configurable output directories  
8. Allows disabling USB monitoring (`--no-usb-monitor`)  
9. Supports custom USB mount letters (default: `D:\`)  
10. Performs automatic crash detection and generates recovery digests  

---

## System Architecture

<INSERT LATER>
  
```
U-See-Bus/
│
├── main.py
│ • Entry point; argument handling
│ • Verification mode
│ • Path conflict detection
│
├── monitor.py
│ • Core monitoring engine
│ • Handles event queue, file/exec events, hash chain updates
│ • Session & digest creation
│
├── usb.py
│ • USB insertion/removal detection via polling
│ • Creates/removes USB filesystem observers
│ • Extracts USB metadata (label, serial, PNP ID)
│
├── events.py
│ • Watchdog filesystem listener (create/modify/delete/move)
│ • File hashing & movement detection logic
│
├── models.py
│ • Dataclasses: FileEvent, ExecEvent, ChainEntry
│ • ChainEntry constructs SHA-256 chained integrity blocks
│
├── chain.py
│ • Recomputes & validates hash chain for verification
│
├── recovery.py
│ • Detects unclean shutdowns using .running marker
│ • Auto-generates recovery digest files
│
├── utils.py
│ • Time helpers
│ • SHA-256 hashing
│ • Atomic JSON writes using temporary files
│
├── harmless_test.py
│ • Builds a harmless USB test executable (PyInstaller)
│
└── usb-reports/
├── usb-sessions/ - session JSON logs
└── final-digest/ - digest summaries
```


---

## Dependencies

All dependencies are listed in:
requirements.txt

To install them, follow the steps in **Installation**.

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/y2git/ICT3215-Digital-Forensics.git
cd ICT3215-Digital-Forensics

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
python main.py
```

Specify folders to monitor
```bash
python main.py --paths "C:\Users\<User>\Desktop" "C:\Evidence"
```

Disable USB monitoring
```bash
python main.py --no-usb-monitor
```

Custom output directories
```bash
python main.py --outdir <base_directory> <session_directory> <digest_directory>
```

Example:
```bash
python main.py --outdir "usb-reports" "usb-sessions" "final-digest"
```
Custom USB mount letter
```bash
python main.py --usb-mount "E:\\"
```

Verify an existing session or digest
```bash
python main.py --verify path/to/usb_session_<timestamp>.json
```

```bash
python main.py --verify path/to/final_digest_<timestamp>.json
```

---

## Output

Session Log (usb_session_<timestamp>.json)

Contains:
```bash
• File events
• USB detection events
• Executable events
• Full hash chain
```
<INSERT usb_session SCREENSHOTS>



Event log with file & process activity and hash chain
Contains
```bash
<TEMPLATE>
```
<INSERT final_digest SCREENSHOTS>



Final Digest (final_digest_<timestamp>.json)
Final digest used for verification with USB_session file's SHA256 hash and with final chain hash

<INSERT usb_reports folder SCREENSHOTS>

Root directory for generated files that holds the sub-folders (IDK TO REMOVE OR NOT)
Contains:
```bash
• SHA-256 hash of session file
• Final chain hash
• Total event count
•Metadata summary
```
<INSERT usb_session SCREENSHOTS>


Output Directory Structure
By default:
```
usb-reports/
│
├── usb-sessions/
│     └── usb_session_<timestamp>.json
│
└── final-digest/
      └── final_digest_<timestamp>.json
```

---

## Verification

U-See Bus supports offline validation of evidence integrity

When executed with the session JSON file, it recomputes every link in the chain and checks the hash for any changes.

When executed with with the final digest JSON file, it compares the session_sha256 in the digest with the SHA256 of the current session file. If it is the same, it reconstructs the event chain and comapres with the final_chain_hash to determine if there is any tampering

If there is no tampering detected in session JSON:

<INSERT SCREENSHOT OF SUCCESSFUL FOR SESSION>

If there is no tampering detected in final digest JSON:

<INSERT SCREENSHOT OF SUCCESSFUL FOR FINAL DIGEST>

If there is tampering detected in session JSON:

<INSERT SCREENSHOT OF UNSUCCESSFUL FOR SESSION>

If there is tampering detected in final digest JSON:

<INSERT SCREENSHOT OF UNSUCCESSFUL FOR FINAL DIGEST>

---

## Limitations

1. Supports Windows 10 and 11 only (due to PowerShell wmic dependency)
2. Safe removal of USB may not work unless --no-usb-monitor is used
3. Not compatible with macOS or Linux
4. Only detects removable flash drives (not SSDs, HDDs, or phones)
5. Large files may increase hashing time during modification events

---
