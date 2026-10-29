import hashlib
from pathlib import Path


def crack_sha1_hash(hash, use_salts=False):
    """Find a password by hashing dictionary entries and optional salts."""
    directory = Path(__file__).resolve().parent
    salts = []
    if use_salts:
        salts = (directory / "known-salts.txt").read_text(
            encoding="utf-8"
        ).splitlines()

    with (directory / "top-10000-passwords.txt").open(encoding="utf-8") as passwords:
        for line in passwords:
            password = line.rstrip("\r\n")
            if use_salts:
                for salt in salts:
                    for candidate in (salt + password, password + salt):
                        if hashlib.sha1(candidate.encode("utf-8")).hexdigest() == hash:
                            return password
            elif hashlib.sha1(password.encode("utf-8")).hexdigest() == hash:
                return password

    return "PASSWORD NOT IN DATABASE"
