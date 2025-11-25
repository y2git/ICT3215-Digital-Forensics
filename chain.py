import hashlib

# Function to verify the integrity of the chain
def verify_chain(entries):
    previous = "0"*64 # intial previous hash is 64 zeros
    for i, event in enumerate(entries): # iterate through each event in the chain
        payload = f"{event['timestamp_sgt']}|{event['event_type']}|{event['data']}|{event['prev_hash']}".encode() # reconstruct the payload using event
        current_hash = hashlib.sha256(payload).hexdigest() # compute the hash of the payload
        
        # check if the current hash matches the stored hash and if the previous hash matches 
        if current_hash != event["hash"] or event["prev_hash"] != previous:
            print(f"[!] Tamper detected at entry {i}") # print where the tampering is detected, count from 0
            return False
        previous = event["hash"] # update previous hash for next iteration
    print("[✓] Chain verified OK; final digest:", previous) # if no tampering detected, print this
    return True
