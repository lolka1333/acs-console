#!/usr/bin/env python3
"""crack_acs_digest.py — recover the ACS password from a captured Digest auth.

If the router refuses Basic and authenticates with Digest, the ACS only sees a
hash, not the plaintext. This brute-forces the password offline:

    response = MD5( HA1 : nonce : nc : cnonce : qop : HA2 )
    HA1 = MD5(username : realm : password)
    HA2 = MD5(method : uri)

We know everything except `password`, so we try candidates until `response`
matches.

Usage
  python crack_acs_digest.py                       # crack captures in data/captures.jsonl
  python crack_acs_digest.py data/captures.jsonl   # explicit capture file
  python crack_acs_digest.py --wordlist rockyou.txt
"""
from __future__ import annotations
import argparse
import hashlib
import itertools
import json
import os
import string
import sys


def md5(s):
    return hashlib.md5(s.encode("utf-8", "latin-1")).hexdigest() if isinstance(s, str) \
        else hashlib.md5(s).hexdigest()


def digest_response(rec, password):
    ha1 = md5(f"{rec['username']}:{rec['realm']}:{password}")
    ha2 = md5(f"{rec.get('method','POST')}:{rec['uri']}")
    if rec.get("qop"):
        return md5(f"{ha1}:{rec['nonce']}:{rec['nc']}:{rec['cnonce']}:{rec['qop']}:{ha2}")
    return md5(f"{ha1}:{rec['nonce']}:{ha2}")


def candidates(rec, wordlist):
    # high-probability guesses first
    seed = ["123456", "1234", "12345678", "password", "admin", "ag", "Acs", "acs",
            "mgts", "mtsoao", "MGTS", "0000", "1111", rec.get("username", ""),
            "serial", "support", "Sercomm", "sercomm", "rv6699", "RV6699"]
    seen = set()
    for c in seed:
        if c and c not in seen:
            seen.add(c); yield c
    if wordlist and os.path.exists(wordlist):
        with open(wordlist, encoding="latin-1", errors="ignore") as f:
            for line in f:
                w = line.rstrip("\r\n")
                if w and w not in seen:
                    seen.add(w); yield w


def brute_short(rec, maxlen=5, charset=string.digits):
    for n in range(1, maxlen + 1):
        for combo in itertools.product(charset, repeat=n):
            yield "".join(combo)


def crack(rec, wordlist, do_brute, brute_max):
    target = (rec.get("response") or "").lower()
    if not target:
        return None
    tried = 0
    for pw in candidates(rec, wordlist):
        tried += 1
        if digest_response(rec, pw).lower() == target:
            return pw, tried
    if do_brute:
        for pw in brute_short(rec, brute_max):
            tried += 1
            if digest_response(rec, pw).lower() == target:
                return pw, tried
            if tried % 200000 == 0:
                print(f"   …{tried} tried", file=sys.stderr)
    return None, tried


def load_records(path):
    recs = []
    if path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    recs.append(json.loads(line))
    else:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        recs = data if isinstance(data, list) else data.get("captures", [])
    return [r for r in recs if r.get("scheme") == "digest"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("capture", nargs="?", default=os.path.join("data", "captures.jsonl"))
    ap.add_argument("--wordlist", default=None, help="optional wordlist file")
    ap.add_argument("--brute", action="store_true", help="also brute-force short numeric PINs")
    ap.add_argument("--brute-max", type=int, default=6)
    args = ap.parse_args()

    if not os.path.exists(args.capture):
        print(f"no capture file: {args.capture}\n"
              f"run the ACS with --capture, point the router at it, then re-run this.")
        return 1
    recs = load_records(args.capture)
    if not recs:
        print("no Digest captures found (maybe you captured Basic = plaintext already?)")
        return 0

    rc = 1
    for rec in recs:
        print(f"\n[*] Digest capture: username='{rec.get('username')}' realm='{rec.get('realm')}' "
              f"uri='{rec.get('uri')}' response={rec.get('response')}")
        found, tried = crack(rec, args.wordlist, args.brute, args.brute_max)
        if found:
            print(f"    [+] PASSWORD FOUND after {tried} tries:  {found!r}")
            rc = 0
        else:
            print(f"    [-] not found ({tried} tries). Try --wordlist rockyou.txt --brute")
    return rc


if __name__ == "__main__":
    sys.exit(main())
