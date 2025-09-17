from pathlib import Path

BASE = [
    "password", "letmein", "welcome", "admin", "qwerty", "abc123", "iloveyou", "monkey",
    "dragon", "sunshine", "flower", "freedom", "login", "master", "hello", "passw0rd"
]

MUTATIONS = [
    lambda s: s,
    lambda s: s.capitalize(),
    lambda s: s.upper(),
    lambda s: s + "123",
    lambda s: s + "!",
    lambda s: s + "2025",
    lambda s: s.replace("o", "0"),
    lambda s: s.replace("i", "1"),
    lambda s: s + "@home",
]

def make_wordlist(size: int = 500, filename: str = "hash_cracker\\wordlist.txt"):
    out = []
    i = 0
    while len(out) < size:
        base = BASE[i % len(BASE)]
        for m in MUTATIONS:
            if len(out) >= size:
                break
            try:
                out.append(m(base))
            except Exception:
                out.append(base)
        i += 1
    
    seen = set()
    final = []
    for w in out:
        if w not in seen:
            seen.add(w)
            final.append(w)
    p = Path(filename)
    p.write_text("\n".join(final), encoding="utf-8")
    print(f"wrote {len(final)} words to {p.resolve()}")

if __name__ == "__main__":
    make_wordlist(size=100)

