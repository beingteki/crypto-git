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
import sys
import time
from functools import partial
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
               message_bytes: int, fn: Optional[Callable[[], object]] = None,
               runs: int = NORMAL_RUNS,
               prepare: Optional[Callable[[], Callable[[], object]]] = None) -> None:
    """Time each call independently after any per-run preparation."""
    measurements = []
    for run in range(runs):
        operation_call = fn if prepare is None else prepare()
        assert operation_call is not None
        start = time.perf_counter_ns()
        result = operation_call()
        elapsed = time.perf_counter_ns() - start
        del result
        measurements.append([part, algorithm, operation, message_bytes, run, elapsed])
    writer.writerows(measurements)
    print(f"{part:9} {algorithm:20} {operation:12} size={message_bytes}: {runs} runs", flush=True)


def rsa_oaep_encapsulate(public_key, oaep):
    return public_key.encrypt(os.urandom(32), oaep)


def ecdh_encapsulate(curve, public_key, exchange):
    ephemeral = ec.generate_private_key(curve)
    secret = ephemeral.exchange(exchange, public_key)
    ciphertext = ephemeral.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    return secret, ciphertext


def ecdh_decapsulate(private_key, curve, exchange, ciphertext):
    ephemeral_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, ciphertext)
    return private_key.exchange(exchange, ephemeral_public_key)


def x25519_encapsulate(public_key):
    ephemeral = x25519.X25519PrivateKey.generate()
    secret = ephemeral.exchange(public_key)
    ciphertext = ephemeral.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return secret, ciphertext


def x25519_decapsulate(private_key, ciphertext):
    return private_key.exchange(x25519.X25519PublicKey.from_public_bytes(ciphertext))


def run_kem(writer):
    sha256 = hashes.SHA256()
    oaep = padding.OAEP(mgf=padding.MGF1(sha256), algorithm=sha256, label=None)
    for bits, name in [(3072, "RSA-OAEP-3072"), (7680, "RSA-OAEP-7680")]:
        generate = partial(rsa.generate_private_key, public_exponent=65537, key_size=bits)
        timed_rows(writer, "kem", name, "keygen", 0, generate, runs=RSA_KEYGEN_RUNS)
        receiver = generate()
        encapsulate = partial(rsa_oaep_encapsulate, receiver.public_key(), oaep)
        ciphertext = encapsulate()
        timed_rows(writer, "kem", name, "encapsulate", 0, encapsulate)
        timed_rows(writer, "kem", name, "decapsulate", 0, partial(receiver.decrypt, ciphertext, oaep))

    curves = [
        ("ECDH-P-256", ec.SECP256R1()),
        ("ECDH-P-384", ec.SECP384R1()),
        ("ECDH-P-521", ec.SECP521R1()),
    ]
    exchange = ec.ECDH()
    for name, curve in curves:
        generate = partial(ec.generate_private_key, curve)
        timed_rows(writer, "kem", name, "keygen", 0, generate)
        receiver = generate()
        encapsulate = partial(ecdh_encapsulate, curve, receiver.public_key(), exchange)
        _, ciphertext = encapsulate()
        timed_rows(writer, "kem", name, "encapsulate", 0, encapsulate)
        timed_rows(writer, "kem", name, "decapsulate", 0,
                   partial(ecdh_decapsulate, receiver, curve, exchange, ciphertext))

    timed_rows(writer, "kem", "X25519", "keygen", 0, x25519.X25519PrivateKey.generate)
    receiver = x25519.X25519PrivateKey.generate()
    encapsulate = partial(x25519_encapsulate, receiver.public_key())
    _, ciphertext = encapsulate()
    timed_rows(writer, "kem", "X25519", "encapsulate", 0, encapsulate)
    timed_rows(writer, "kem", "X25519", "decapsulate", 0,
               partial(x25519_decapsulate, receiver, ciphertext))

    # Post-quantum KEMs
    for name, cls in [("ML-KEM-768", MLKEM768PrivateKey),
                      ("ML-KEM-1024", MLKEM1024PrivateKey)]:
        timed_rows(writer, "kem", name, "keygen", 0, cls.generate)
        receiver = cls.generate()
        encapsulate = receiver.public_key().encapsulate
        _, ciphertext = encapsulate()
        timed_rows(writer, "kem", name, "encapsulate", 0, encapsulate)
        timed_rows(writer, "kem", name, "decapsulate", 0, partial(receiver.decapsulate, ciphertext))


def run_signatures(writer):
    sha256 = hashes.SHA256()
    pss = padding.PSS(mgf=padding.MGF1(sha256), salt_length=sha256.digest_size)
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
        if is_rsa:
            options = (pss, sha256)
        elif digest is not None:
            options = (ec.ECDSA(digest),)
        else:
            options = ()
        sign = partial(private_key.sign, MESSAGE, *options)
        signature = sign()
        verify = partial(public_key.verify, signature, MESSAGE, *options)
        timed_rows(writer, "signature", name, "sign", 0, sign)
        timed_rows(writer, "signature", name, "verify", 0, verify)


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
            encrypt = cipher.encrypt

            def prepare_encrypt():
                return partial(encrypt, os.urandom(12), message, None)

            timed_rows(writer, "aead", name, "encrypt", size, prepare=prepare_encrypt)
            fixed_nonce = os.urandom(12)
            fixed_ciphertext = cipher.encrypt(fixed_nonce, message, None)
            timed_rows(writer, "aead", name, "decrypt", size,
                       partial(cipher.decrypt, fixed_nonce, fixed_ciphertext, None))


def environment_metadata():
    import ssl
    try:
        cpu = platform.processor() or "Not reported by platform.processor()"
    except Exception:
        cpu = "Unknown"
    return {
        "python": sys.version.replace("\n", " "),
        "cryptography": cryptography.__version__,
        "cryptography_backend_openssl": backend.openssl_version_text(),
        "python_ssl_module_openssl": ssl.OPENSSL_VERSION,
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
    try:
        out.mkdir(parents=True, exist_ok=False)
    except FileExistsError:
        parser.error(f"Output directory already exists. Choose a new path: {out}")
    metadata = environment_metadata()
    with (out / "environment.txt").open("x", encoding="utf-8") as f:
        for key, value in metadata.items():
            f.write(f"{key}: {value}\n")
    raw_path = out / "raw.csv"
    with raw_path.open("x", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(HEADER)
        run_kem(writer)
        run_signatures(writer)
        run_aead(writer)
    print(f"\nCompleted. Raw measurements: {raw_path}")
    print("Do not edit raw.csv. Preserve this file as the original measurement record.")


if __name__ == "__main__":
    main()
