from concurrent.futures import ThreadPoolExecutor
import hashlib
from pathlib import Path
from threading import Event

def hash_func(plaintext: str, algo: str = "sha256") -> str:
    return hashlib.new(algo, plaintext.encode()).hexdigest()

def read_first_nonempty_line(path: Path):
    if not path.exists():
        return None
    with path.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if s:
                return s
    return None

def start_cracker(target_hash: str = None, wordlist_path: str = None, algo: str = "sha256", max_workers: int = 8) -> str:
    if target_hash is None:
        target_hash = read_first_nonempty_line(Path("hash_cracker\\targets.txt"))
        if target_hash is None:
            raise ValueError("no target hash provided or target.txt is empty")
    if wordlist_path is None:
        wordlist_path = "hash_cracker\\wordlist.txt"
    
    target_hash = target_hash.strip().lower()
    wordlist_file = Path(wordlist_path)
    if not wordlist_file.exists():
        raise FileNotFoundError(f"wordlist file not found: {wordlist_file}")
    
    with wordlist_file.open("r", encoding="utf-8", errors="ignore") as f:
        words = [w.strip() for w in f if w.strip()]
    
    stop_event = Event()
    found_plain = None

    def worker(word: str):
        nonlocal found_plain
        if stop_event.is_set():
            return None
        try:
            h = hash_func(word, algo)
        except Exception:
            raise
        if h == target_hash:
            found_plain = word
            stop_event.set()
            return word
        return None
    
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = []
        chunk_size = 2048
        for i in range(0, len(words), chunk_size):
            if stop_event.is_set():
                break
            chunk = words[i:i+chunk_size]
            for w in chunk:
                futures.append(ex.submit(worker, w))
            
            for fut in futures:
                if fut.done():
                    res = fut.result()
                    if res:
                        break

            if stop_event.is_set():
                break

        if stop_event.is_set():
            pass
    
    if found_plain:
        print("cracked!")
        print(f"hash: {target_hash}")
        print(f"word: {found_plain}")
        return found_plain
    
    return None

def start():
    print("===== hash cracker =====")
    try:
        target_hash = input("enter target hash: ").strip()
        wordlist_path = input("enter path to wordlist file: ").strip()
        algo = input("enter algo to use (default is sha256): ").strip()
        
        if not algo:
            algo = "sha256"

        result = start_cracker(target_hash, wordlist_path, algo, max_workers=8)

        if not result:
            print("no match found")
    except FileNotFoundError as e:
        print(f"file error: {e}")
    except ValueError as e:
        print(f"value error: {e}")
        print("chk algorithm names")
    except KeyboardInterrupt:
        print("\nstooped by user")
    except Exception:
        print("unexpected error")