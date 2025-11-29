# ICT3215-U-See_Bus

U-See Bus is a Python script that is used to detect the insertion and removal of USB thumbdrives and to detect changes made to files within the folders it is monitoring (Downloads, Documents and Desktop by default).  

It also logs any `.exe` files run by USB drives and uses cryptographic chains to ensure forensic integrity.

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

<img width="221" height="455" alt="image" src="https://github.com/user-attachments/assets/9e7c0b6c-e0fa-4805-8187-6a477d552995" />

---

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
│ • Runtime Freeze Detection
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
git clone https://github.com/y2git/ICT3215-U-See_Bus.git
cd ICT3215-U-See_Bus

# 2. Create a virtual environment
python -m venv .venv

# 3. Activate the virtual environment
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

Session Log (usb_session_[timestamp].json)

Contains:
```bash
• File events
• USB detection events
• Executable events
• Full hash chain
```
<img width="858" height="625" alt="image" src="https://github.com/user-attachments/assets/524f9cf0-f0f1-4524-947a-fffae5d7cbe6" />


Final Digest (final_digest_[timestamp].json)
Final digest used for verification with USB_session file's SHA256 hash and with final chain hash
Contains:
```bash
• Number of events that occurred and what they are
• File path to the respective session log
• The final hash of the session log when final digest was generated

```
<img width="897" height="447" alt="image" src="https://github.com/user-attachments/assets/c0b8e58e-a4f0-4fd4-8242-1f0bfb92b15c" />



Root directory for generated files that holds the sub-folders (IDK TO REMOVE OR NOT)
Contains:
```bash
• usb_session folder
• final_digest folder
```
<img width="218" height="145" alt="image" src="https://github.com/user-attachments/assets/02454149-f755-47c1-b8a7-d539eec67d74" />


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
### Detect if reports were modified
U-See Bus supports offline validation of evidence integrity

When executed with the session JSON file, it recomputes every link in the chain and checks the hash for any changes.

When executed with with the final digest JSON file, it compares the session_sha256 in the digest with the SHA256 of the current session file. If it is the same, it reconstructs the event chain and comapres with the final_chain_hash to determine if there is any tampering

If there is no tampering detected in session JSON:

<img width="1189" height="240" alt="image" src="https://github.com/user-attachments/assets/423a3afc-2a80-4f8c-8957-04dac80a8866" />


If there is no tampering detected in final digest JSON:

<img width="1150" height="334" alt="image" src="https://github.com/user-attachments/assets/f35f9bdb-d8a9-4b75-a81f-1443f2be208a" />


If there is tampering detected in session JSON:

<img width="1169" height="212" alt="image" src="https://github.com/user-attachments/assets/247c194e-157f-4bcc-9d5d-1f8c71c00354" />


If there is tampering detected in final digest JSON:

<img width="1165" height="287" alt="image" src="https://github.com/user-attachments/assets/c8d59ebd-b165-4342-bea6-be00a4c75f97" />

### Detect if U-See Bus was stopped unnaturally
U-See Bus has a feature to detect if it was terminated in an unintended manner. When U-See Bus is executed a ".running" file will be generated and it will be deleted only when it is terminated gracefully with CTRL+C

<img width="208" height="152" alt="image" src="https://github.com/user-attachments/assets/f17d2f5e-03a1-4b55-ae30-7e8e6cb6fc9c" />

In the case that U-See Bus was not terminated in the intended manner, ".running" will remain in the folder and it will trigger an alert and a unique final digest file generation the next time it is run.
<img width="1416" height="650" alt="image" src="https://github.com/user-attachments/assets/489d0d7e-f218-4b79-926b-775b1f8001f5" />

Within the final_digest_unclean_[timestamp].json, it contains the similar values to the normal final digest except the information regarding events that had taken place and instead it has a "note" section
<img width="987" height="287" alt="image" src="https://github.com/user-attachments/assets/0b9195e2-c560-4248-830e-67b144c55988" />

### Detect if U-See Bus was frozen during execution
U-See Bus has a feature to detect if it becomes unresponsive during monitoring; when a runtime freeze is detected, it records a "runtime_freeze_detected" event and generates a forced_digest_[timestamp].json snapshot.  
<img width="507" height="262" alt="image" src="https://github.com/user-attachments/assets/efe0dbec-4bf8-4d3d-b60f-0d9fb3e7849b" />

In the case that U-See Bus becomes frozen, a "runtime_freeze_detected" entry is added to the chain and a forced digest is created to show the state of the session at the freeze moment.  
<img width="507" height="133" alt="image" src="https://github.com/user-attachments/assets/9728d5eb-1ce6-489f-ba2c-b446ebd8bc77" />

Forced digest verification compares the stored session_sha256 with the current hash of the session file to determine if the session was modified after the freeze event.  
<img width="507" height="132" alt="image" src="https://github.com/user-attachments/assets/37dbe0ca-8056-4939-926b-61a7310dc852" />

---

## Limitations

1. Supports Windows 10 and 11 only (due to PowerShell wmic dependency)
2. Safe removal of USB may not work unless --no-usb-monitor is used
3. Not compatible with macOS or Linux
4. Only detects removable flash drives (not SSDs, HDDs, or phones)
5. Large files may increase hashing time during modification events

---
