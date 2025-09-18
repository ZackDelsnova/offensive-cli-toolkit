from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
import socket
import sys

def resolve(hostname: str, timeout: Optional[float]) -> Optional[str]:
    if timeout is not None:
        socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyname(hostname)
    except Exception:
        return None

def enumerate_subdomain(domain: str, wordlist_file: Optional[str] = None, workers: int = 20, timeout: Optional[float] = 3.0) -> Dict[str, Optional[str]]:
    if wordlist_file:
        try:
            with open(wordlist_file, "r", encoding="utf-8") as f:
                words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
        except FileNotFoundError:
            raise
    
    targets = [f"{w}.{domain}" for w in words]
    results: Dict[str, Optional[str]] = {}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(resolve, host, timeout): host for host in targets}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                ip = fut.result()
            except Exception:
                ip = None
            results[host] = ip
    
    return results

def start():
    print("===== subdomain enumerator =====")
    domain = input("enter domain (like example.com): ").strip()
    if not domain:
        print("no domain provided")
        return
    
    wordlist_path = input("enter path to wordlist file (or press enter to use default wordlist): ").strip() or "subdomain\\wordlist.txt"
    
    try:
        workers_raw = input("enter workers [default 50]: ").strip()
        workers = int(workers_raw) if workers_raw else 50
        if workers < 1:
            raise ValueError
    except Exception:
        workers = 50

    try:
        timeout_raw = input("enter socket timeout seconds [default 3.0]: ").strip()
        timeout = float(timeout_raw) if timeout_raw else 3.0
    except Exception:
        timeout = 3.0

    verbose = input("verbose? (y/n): ").strip().lower() == 'y'

    out = input("write result to file (enter path or press enter to skip)").strip().lower() or None

    print(f"starting enumeration domain={domain} workers={workers} timeout={timeout} wordlist={'file '+wordlist_path if wordlist_path else 'subdomain\\wordlist.txt'}")
    try:
        results = enumerate_subdomain(domain, wordlist_path, workers, timeout)
    except FileNotFoundError:
        print(f"wordlist file not found {wordlist_path}")
        return
    except Exception as e:
        print(f"error: {e}")
        return

    found = {h: ip for h, ip in results.items() if ip}
    if not found:
        print("no subdomain found")
    else:
        print(f"found {len(found)} subdomains: ")
        for host, ip in sorted(found.items()):
            print(f"{host} -> {ip}")
    
    if verbose:
        print("\n=== all targets (including failures) ===")
        for host, ip in sorted(results.items()):
            print(f"{host}\t{ip or 'notfound'}")
    
    if out:
        try:
            with open(out, "w", encoding="utf-8") as f:
                for host, ip in sorted(results.items()):
                    f.write(f"{host}\t{ip or ''}")
            print(f"results written to outfile")
        except Exception as e:
            print(f"failed to write {e}")
             