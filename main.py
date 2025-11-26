import argparse, os, json, sys
from pathlib import Path

from monitor import run_monitor
from chain import verify_chain
from utils import file_sha256

# Program Banner
print("""
===========================
   U - S E E   B U S
   USB Activity Monitor
===========================
""")

def main():

    parser=argparse.ArgumentParser(description="USB Activity Correlator (Demonstration Enhanced)")
    parser.add_argument("--paths",nargs="*",help="Extra directories to monitor. Usage: python U-See_Bus.py --paths 'C:\\path1' 'D:\\path2' ",default=[]) # usage: python U-See_Bus.py -- --paths "C:\\path1" "D:\\path2"
    parser.add_argument("--no-usb-monitor",action="store_true",help="Disable USB monitoring")
    parser.add_argument("--verify",help="Verify integrity of a saved JSON report. Usage: python U-See_Bus.py --verify /path/to/usb_session_<timestamp>.json or /path/to/final_digest_<timestamp>.json")
    parser.add_argument("--outdir",default=["usb-reports", "usb-sessions", "final-digest"],help="Output directory for reports. Usage: python U-See_Bus.py --outdir '<base_dir>' '<session_dir>' '<digest_dir>'", nargs=3)
    parser.add_argument("--usb-mount",default="D:\\",help="Drive letter for USB (Windows default: D:\\). Usage: python U-See_Bus.py --usb-mount '<Letter i.e E>:\\'")
    args=parser.parse_args()

    if args.verify:
        data = json.loads(Path(args.verify).read_text()) # load the JSON selected for verification
        
        # if it is session JSON
        if isinstance(data, dict) and "chain" in data:
            verify_chain(data["chain"])  # verify only the chain list
            sys.exit(0)

        # if it is final digest JSON
        if isinstance(data, dict) and "session_path" in data and "session_sha256" in data: # Check for required keys
            session_path = Path(data["session_path"]) # get the session path from digest
            if not session_path.exists(): # check if session file exists
                print(f"[!] Session file not found: {session_path}")
                sys.exit(1)
            expected_hash = file_sha256(session_path) # compute the sha256 of the session file
            print(f"[*] Checking session hash for {session_path.name}")
            print(f"    expected: {expected_hash}")
            print(f"    actual:   {data['session_sha256']}")

            if expected_hash != data["session_sha256"]: # compare expected and actual hash
                print("[!] Session file hash mismatch — possible tampering!") # print message if hashes are different
                sys.exit(1)

            # Load session JSON and verify the chain
            session_data = json.loads(session_path.read_text(encoding="utf-8"))
            if "chain" not in session_data: # check if chain exists in session data
                print("[!] Session file has no 'chain' array. Either wrong file, or tampering has occurred to remove chain.") # print message if chain is missing
                sys.exit(1)

            verify_chain(session_data["chain"]) # verify the chain integrity
            expected_recomputed_final = session_data["chain"][-1]["hash"] # get the final hash from the chain

            print(f"[*] Expected final_chain_hash: {expected_recomputed_final}") # print expected final chain hash
            print(f"[*] Current chain end hash:    {data['final_chain_hash']}") # print current chain end hash from digest

            # Compare the recomputed final hash with the one in the digest
            if expected_recomputed_final != data["final_chain_hash"]:
                print("[!] Chain hash mismatch — session altered after digest creation!")
                sys.exit(1)

            # If all checks pass
            print("[✓] Final digest verification succeeded. Session integrity intact.")
            sys.exit(0)


    # Prepare local paths to monitor
    HOME=str(Path.home())
    local_paths=[os.path.join(HOME,d) for d in ["Downloads","Documents","OneDrive\\Desktop"] if os.path.isdir(os.path.join(HOME,d))]
    local_paths.extend(args.paths)

    run_monitor(local_paths,args.usb_mount,args.outdir,monitor_usb=not args.no_usb_monitor)


if __name__=="__main__":
    main()
