import binascii
import hashlib
import os
from pathlib import Path

def make_unsalted_hashes(plaintext, algo="sha256", target_file="hash_cracker\\targets.txt", reference_file="hash_cracker\\hashes_with_plain.txt"):
    lines_target = []
    lines_ref = []
    for p in plaintext:
        h = hashlib.new(algo, p.encode()).hexdigest()
        lines_target.append(h)
        lines_ref.append(f"{h} {p}")
    Path(target_file).write_text("\n".join(lines_target), encoding="utf-8")
    Path(reference_file).write_text("\n".join(lines_ref), encoding="utf-8")
    print(f"wrote {len(plaintext)} targets to {target_file} and reference to {reference_file}")

def make_pbkdf2_example(password: str, iterations: int = 100_000):
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)
    return {
        "salt_hex": binascii.hexlify(salt).decode(),
        "dk_hex": binascii.hexlify(dk).decode(),
        "iterations": iterations
    }

if __name__ == "__main__":
    # small set you can edit
    sample_plain = ["password", "Password123", "letmein", "admin", "unique_test_01"]
    make_unsalted_hashes(sample_plain, algo="sha256")

    # print a pbkdf2 example (not for the cracker; just to show slow/salted example)
    pb = make_pbkdf2_example("Password123", iterations=100_000)
    print("\pbkdf2 example (for learning):")
    print(f"iterations: {pb['iterations']}")
    print(f"salt: {pb['salt_hex']}")
    print(f"derived_key: {pb['dk_hex']}")