#!/usr/bin/env python3
"""Verify what the app actually persisted, from its own SwiftData store.

Reads the contact row whose identifier is the impersonated wallet address, then
decodes the prekey bundle the app stored for it and compares the key material
with the keys the generated attack card carried.

Exit 0 only when the row exists AND the stored bundle is the attacker's bundle.
"""

import base64
import json
import sqlite3
import zlib
import sys
from pathlib import Path


def fingerprint(raw: bytes) -> str:
    import hashlib
    return hashlib.sha256(raw).hexdigest()[:16]


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: verify_store.py <store> <attack.json> <impersonated address>", file=sys.stderr)
        return 2

    store, card_json, address = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]

    expected = json.loads(card_json.read_text())
    expected_ik = base64.b64decode(expected["attacker_secrets"]["dh_identity_public"])

    # The generator emits the card as a compressed payload, exactly as it travels
    # in the link. Expand it the same way the app does and read the bundle out.
    payload = expected["payload"]
    padded = payload + "=" * (-len(payload) % 4)
    card = json.loads(zlib.decompressobj(-15).decompress(base64.urlsafe_b64decode(padded)))
    expected_bundle = json.loads(base64.b64decode(card["bundle"]))

    con = sqlite3.connect(f"file:{store}?mode=ro", uri=True)
    rows = con.execute(
        "select ZDISPLAYNAME, ZID, ZPREKEYBUNDLEBASE64 from ZCONTACT where ZID = ?",
        (address,),
    ).fetchall()
    con.close()

    print("=== stored contact for the impersonated address ===")
    if not rows:
        print(f"NO ROW: no contact stored with id {address}")
        return 1

    for name, cid, bundle_b64 in rows:
        print(f"display name : {name!r}")
        print(f"contact id   : {cid}")
        raw = base64.b64decode(bundle_b64)
        print(f"bundle bytes : {len(raw)}")
        stored = json.loads(raw)
        stored_ik = base64.b64decode(stored["dhIdentityKey"])

        print(f"stored   dhIdentityKey fingerprint : {fingerprint(stored_ik)}")
        print(f"attacker dhIdentityKey fingerprint : {fingerprint(expected_ik)}")

        keys_match = stored == expected_bundle
        unsigned = "walletAddress" not in stored and "walletSignature" not in stored

        print(f"stored bundle == attacker bundle   : {keys_match}")
        print(f"bundle carries no wallet binding   : {unsigned}")
        print(f"display name is attacker chosen    : {name == expected['nickname']}")
        print(f"expected nickname                  : {expected['nickname']!r}")

        if not keys_match:
            print("VERDICT: FAIL — the app stored a different bundle than the attack card carried")
            return 1
        if not unsigned:
            print("VERDICT: FAIL — the stored bundle unexpectedly carries wallet binding fields")
            return 1

    print("VERDICT: PASS — the app persisted the attacker's bundle under the impersonated address")
    return 0


if __name__ == "__main__":
    sys.exit(main())
