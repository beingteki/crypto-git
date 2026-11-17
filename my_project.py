#!/usr/bin/env python3
"""CryptoBench: reproducible cryptographic micro-benchmarks.

Run:
    python my_project.py results/run-1
    python my_project.py results/run-2

Requires Python 3.9+ and pyca/cryptography >= 50.0.
All timings are genuine measurements from the machine on which this script runs.
"""
from __future__ import annotations

import argparse
import csv
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Callable, Optional

try:
    import cryptography
    from cryptography.hazmat.backends.openssl.backend import backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, x25519
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV, ChaCha20Poly1305
    from cryptography.hazmat.primitives.asymmetric.mlkem import MLKEM768PrivateKey, MLKEM1024PrivateKey
    from cryptography.hazmat.primitives.asymmetric.mldsa import (
        MLDSA44PrivateKey, MLDSA65PrivateKey, MLDSA87PrivateKey
    )
except ImportError as exc:
    raise SystemExit(
        "Required cryptography APIs are unavailable. Install with "
        "`python -m pip install 'cryptography>=50.0'`. "
        "For ML-KEM/ML-DSA, use a supported backend (cryptography 48+ wheels "
        "with OpenSSL 3.5+ or a supported AWS-LC/BoringSSL build). "
        f"Import error: {exc}"
    )

HEADER = ["part", "algorithm", "operation", "message_bytes", "run", "nanoseconds"]
NORMAL_RUNS = 101
RSA_KEYGEN_RUNS = 21
MESSAGE_SIZES = [64, 1024, 16384, 1048576]
MESSAGE = os.urandom(1024)


def timed_rows(writer, part: str, algorithm: str, operation: str,
               message_bytes: int, fn: Callable[[], object],
               runs: int = NORMAL_RUNS,
               prepare: Optional[Callable[[int], None]] = None) -> None:
    """Time each call independently. Preparation is always outside the clock."""
    for run in range(runs):
        if prepare is not None:
            prepare(run)
        start = time.perf_counter_ns()
        fn()
        elapsed = time.perf_counter_ns() - start
        writer.writerow([part, algorithm, operation, message_bytes, run, elapsed])
        print(f"{part:11} {algorithm:20} {operation:12} run={run:03d} {elapsed:>12} ns",
              flush=True)


def rsa_oaep_encrypt(public_key, data):
    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def run_kem(writer):
    # RSA-OAEP-3072 and RSA-OAEP-7680
    for bits, name in [(3072, "RSA-OAEP-3072"), (7680, "RSA-OAEP-7680")]:
        timed_rows(writer, "kem", name, "keygen", 0,
                   lambda b=bits: rsa.generate_private_key(public_exponent=65537, key_size=b),
                   runs=RSA_KEYGEN_RUNS)
        receiver = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        ciphertext = rsa_oaep_encrypt(receiver.public_key(), os.urandom(32))
        timed_rows(writer, "kem", name, "encapsulate", 0,
                   lambda pk=receiver.public_key(): rsa_oaep_encrypt(pk, os.urandom(32)))
        timed_rows(writer, "kem", name, "decapsulate", 0,
                   lambda sk=receiver, ct=ciphertext: sk.decrypt(
                       ct, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()),
                                        algorithm=hashes.SHA256(), label=None)))

    # ECDH: ephemeral key generation + exchange + public point serialization are timed.
    curves = [
        ("ECDH-P-256", ec.SECP256R1()),
        ("ECDH-P-384", ec.SECP384R1()),
        ("ECDH-P-521", ec.SECP521R1()),
    ]
    for name, curve in curves:
        timed_rows(writer, "kem", name, "keygen", 0,
                   lambda c=curve: ec.generate_private_key(c))
        receiver = ec.generate_private_key(curve)
        ephemeral = ec.generate_private_key(curve)
        ciphertext = ephemeral.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        timed_rows(writer, "kem", name, "encapsulate", 0,
                   lambda c=curve, pk=receiver.public_key(): (
                       lambda eph: (eph.exchange(ec.ECDH(), pk),
                                    eph.public_key().public_bytes(
                                        serialization.Encoding.X962,
                                        serialization.PublicFormat.UncompressedPoint))
                   )(ec.generate_private_key(c)))
        timed_rows(writer, "kem", name, "decapsulate", 0,
                   lambda sk=receiver, ct=ciphertext, c=curve:
                   sk.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(c, ct)))

    # X25519
    timed_rows(writer, "kem", "X25519", "keygen", 0, x25519.X25519PrivateKey.generate)
    receiver = x25519.X25519PrivateKey.generate()
    ephemeral = x25519.X25519PrivateKey.generate()
    ciphertext = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    def x_encapsulate():
        eph = x25519.X25519PrivateKey.generate()
        eph.exchange(receiver.public_key())
        return eph.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)
    timed_rows(writer, "kem", "X25519", "encapsulate", 0, x_encapsulate)
    timed_rows(writer, "kem", "X25519", "decapsulate", 0,
               lambda: receiver.exchange(x25519.X25519PublicKey.from_public_bytes(ciphertext)))

    # Post-quantum KEMs
    for name, cls in [("ML-KEM-768", MLKEM768PrivateKey),
                      ("ML-KEM-1024", MLKEM1024PrivateKey)]:
        timed_rows(writer, "kem", name, "keygen", 0, cls.generate)
        receiver = cls.generate()
        _, ciphertext = receiver.public_key().encapsulate()
        timed_rows(writer, "kem", name, "encapsulate", 0,
                   receiver.public_key().encapsulate)
        timed_rows(writer, "kem", name, "decapsulate", 0,
                   lambda sk=receiver, ct=ciphertext: sk.decapsulate(ct))


def rsa_pss_sign(private_key, data):
    return private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )


def rsa_pss_verify(public_key, signature, data):
    return public_key.verify(
        signature, data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )


def run_signatures(writer):
    specs = [
        ("RSA-PSS-3072", lambda: rsa.generate_private_key(public_exponent=65537, key_size=3072),
         hashes.SHA256()),
        ("RSA-PSS-7680", lambda: rsa.generate_private_key(public_exponent=65537, key_size=7680),
         hashes.SHA256()),
        ("ECDSA-P-256", lambda: ec.generate_private_key(ec.SECP256R1()), hashes.SHA256()),
        ("ECDSA-P-384", lambda: ec.generate_private_key(ec.SECP384R1()), hashes.SHA384()),
        ("ECDSA-P-521", lambda: ec.generate_private_key(ec.SECP521R1()), hashes.SHA512()),
        ("Ed25519", ed25519.Ed25519PrivateKey.generate, None),
        ("ML-DSA-44", MLDSA44PrivateKey.generate, None),
        ("ML-DSA-65", MLDSA65PrivateKey.generate, None),
        ("ML-DSA-87", MLDSA87PrivateKey.generate, None),
    ]
    for name, keygen, digest in specs:
        is_rsa = name.startswith("RSA-")
        timed_rows(writer, "signature", name, "keygen", 0, keygen,
                   runs=RSA_KEYGEN_RUNS if is_rsa else NORMAL_RUNS)
        private_key = keygen()  # Setup key pair for sign/verify outside timing.
        public_key = private_key.public_key()
        if name.startswith("RSA-"):
            signature = rsa_pss_sign(private_key, MESSAGE)
            timed_rows(writer, "signature", name, "sign", 0,
                       lambda sk=private_key: rsa_pss_sign(sk, MESSAGE))
            timed_rows(writer, "signature", name, "verify", 0,
                       lambda pk=public_key, sig=signature: rsa_pss_verify(pk, sig, MESSAGE))
        elif name.startswith("ECDSA-"):
            signature = private_key.sign(MESSAGE, ec.ECDSA(digest))
            timed_rows(writer, "signature", name, "sign", 0,
                       lambda sk=private_key, h=digest: sk.sign(MESSAGE, ec.ECDSA(h)))
            timed_rows(writer, "signature", name, "verify", 0,
                       lambda pk=public_key, sig=signature, h=digest:
                       pk.verify(sig, MESSAGE, ec.ECDSA(h)))
        else:
            signature = private_key.sign(MESSAGE)
            timed_rows(writer, "signature", name, "sign", 0,
                       lambda sk=private_key: sk.sign(MESSAGE))
            timed_rows(writer, "signature", name, "verify", 0,
                       lambda pk=public_key, sig=signature: pk.verify(sig, MESSAGE))


def run_aead(writer):
    specs = [
        ("AES-128-GCM", AESGCM, 16),
        ("AES-256-GCM", AESGCM, 32),
        ("ChaCha20-Poly1305", ChaCha20Poly1305, 32),
        ("AES-256-GCM-SIV", AESGCMSIV, 32),
    ]
    for name, cls, key_len in specs:
        for size in MESSAGE_SIZES:
            key = os.urandom(key_len)
            message = os.urandom(size)
            cipher = cls(key)
            nonce_box = {"value": os.urandom(12)}
            # Generate each fresh nonce before the clock, as required by the brief.
            def prepare(_run):
                nonce_box["value"] = os.urandom(12)
            timed_rows(writer, "aead", name, "encrypt", size,
                       lambda c=cipher, m=message, nb=nonce_box:
                       c.encrypt(nb["value"], m, None),
                       prepare=prepare)
            fixed_nonce = os.urandom(12)
            fixed_ciphertext = cipher.encrypt(fixed_nonce, message, None)
            timed_rows(writer, "aead", name, "decrypt", size,
                       lambda c=cipher, n=fixed_nonce, ct=fixed_ciphertext:
                       c.decrypt(n, ct, None))


def environment_metadata():
    import ssl
    try:
        cpu = platform.processor() or "Not reported by platform.processor()"
    except Exception:
        cpu = "Unknown"
    return {
        "python": sys.version.replace("\n", " "),
        "cryptography": cryptography.__version__,
        "openssl": ssl.OPENSSL_VERSION,
        "cpu_model": cpu,
        "architecture": platform.machine(),
        "logical_cores": os.cpu_count(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
    }


def main():
    parser = argparse.ArgumentParser(description="Run CryptoBench measurements.")
    parser.add_argument("output_dir", help="Directory in which raw.csv and environment.txt are written")
    args = parser.parse_args()
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    metadata = environment_metadata()
    with (out / "environment.txt").open("w", encoding="utf-8") as f:
        for key, value in metadata.items():
            f.write(f"{key}: {value}\n")
    raw_path = out / "raw.csv"
    with raw_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        run_kem(writer)
        run_signatures(writer)
        run_aead(writer)
    print(f"\nCompleted. Raw measurements: {raw_path}")
    print("Do not edit raw.csv. Preserve this file as the original measurement record.")


if __name__ == "__main__":
    main()
