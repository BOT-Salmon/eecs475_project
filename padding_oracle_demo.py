#!/usr/bin/env python3
"""
Educational CBC padding oracle demo.

This script implements:
1. AES-CBC encryption with PKCS#7 padding.
2. A deliberately insecure padding oracle that reveals only padding validity.
3. A byte-by-byte padding oracle attack recovering plaintext without the key.
4. A comparison with an AEAD design to illustrate why authenticated encryption blocks
   this style of attack.

Usage:
    python padding_oracle_demo.py
"""

from __future__ import annotations

import argparse
import secrets
from dataclasses import dataclass
from typing import List, Tuple

from Crypto.Cipher import AES

BLOCK_SIZE = 16


def xor_bytes(a: bytes, b: bytes) -> bytes:
    if len(a) != len(b):
        raise ValueError("Inputs to xor_bytes must have the same length.")
    return bytes(x ^ y for x, y in zip(a, b))


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if block_size <= 0 or block_size >= 256:
        raise ValueError("block_size must be between 1 and 255.")
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded message length.")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length byte.")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding pattern.")
    return data[:-pad_len]


def split_blocks(data: bytes, block_size: int = BLOCK_SIZE) -> List[bytes]:
    if len(data) % block_size != 0:
        raise ValueError("Data length must be a multiple of the block size.")
    return [data[i : i + block_size] for i in range(0, len(data), block_size)]


@dataclass
class OracleStats:
    queries: int = 0


class VulnerableCBCSystem:
    """Toy vulnerable system exposing a padding-validity oracle."""

    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(BLOCK_SIZE)
        self.stats = OracleStats()

    def encrypt(self, plaintext: bytes) -> bytes:
        iv = secrets.token_bytes(BLOCK_SIZE)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pkcs7_pad(plaintext, BLOCK_SIZE))
        return iv + ciphertext

    def decrypt_raw(self, iv_ciphertext: bytes) -> bytes:
        if len(iv_ciphertext) < 2 * BLOCK_SIZE or len(iv_ciphertext) % BLOCK_SIZE != 0:
            raise ValueError("Ciphertext must contain IV + at least one ciphertext block.")
        iv = iv_ciphertext[:BLOCK_SIZE]
        ciphertext = iv_ciphertext[BLOCK_SIZE:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return cipher.decrypt(ciphertext)

    def decrypt(self, iv_ciphertext: bytes) -> bytes:
        padded = self.decrypt_raw(iv_ciphertext)
        return pkcs7_unpad(padded, BLOCK_SIZE)

    def padding_oracle(self, iv_ciphertext: bytes) -> bool:
        """Returns True iff the decrypted plaintext has valid PKCS#7 padding."""
        self.stats.queries += 1
        try:
            pkcs7_unpad(self.decrypt_raw(iv_ciphertext), BLOCK_SIZE)
            return True
        except ValueError:
            return False


@dataclass
class BlockRecoveryResult:
    block_index: int
    intermediate: bytes
    plaintext: bytes
    queries_used: int


class PaddingOracleAttacker:
    def __init__(self, oracle_system: VulnerableCBCSystem):
        self.system = oracle_system

    def recover_block(self, prev_block: bytes, target_block: bytes, block_index: int) -> BlockRecoveryResult:
        if len(prev_block) != BLOCK_SIZE or len(target_block) != BLOCK_SIZE:
            raise ValueError("Both blocks must be exactly one AES block.")

        start_queries = self.system.stats.queries
        intermediate = bytearray(BLOCK_SIZE)
        plaintext = bytearray(BLOCK_SIZE)

        # We craft a fresh previous block so that I_i XOR crafted_prev has chosen padding.
        crafted_prev = bytearray(secrets.token_bytes(BLOCK_SIZE))

        for pad_value in range(1, BLOCK_SIZE + 1):
            index = BLOCK_SIZE - pad_value

            # Force the suffix to decrypt to the desired padding value.
            for j in range(index + 1, BLOCK_SIZE):
                crafted_prev[j] = intermediate[j] ^ pad_value

            found_guess = None
            for guess in range(256):
                crafted_prev[index] = guess
                probe = bytes(crafted_prev) + target_block

                if self.system.padding_oracle(probe):
                    # Guard against accidental valid padding for the 0x01 case.
                    if pad_value == 1 and index > 0:
                        probe2 = bytearray(crafted_prev)
                        probe2[index - 1] ^= 1
                        if not self.system.padding_oracle(bytes(probe2) + target_block):
                            continue
                    found_guess = guess
                    break

            if found_guess is None:
                raise RuntimeError(f"No valid padding guess found for byte position {index}.")

            intermediate[index] = found_guess ^ pad_value
            plaintext[index] = intermediate[index] ^ prev_block[index]

        queries_used = self.system.stats.queries - start_queries
        return BlockRecoveryResult(
            block_index=block_index,
            intermediate=bytes(intermediate),
            plaintext=bytes(plaintext),
            queries_used=queries_used,
        )

    def recover_plaintext(self, iv_ciphertext: bytes, verbose: bool = True) -> Tuple[bytes, List[BlockRecoveryResult]]:
        blocks = split_blocks(iv_ciphertext, BLOCK_SIZE)
        if len(blocks) < 2:
            raise ValueError("Need IV plus at least one ciphertext block.")

        recovered_padded = bytearray()
        per_block: List[BlockRecoveryResult] = []

        for i in range(1, len(blocks)):
            result = self.recover_block(blocks[i - 1], blocks[i], block_index=i)
            per_block.append(result)
            recovered_padded.extend(result.plaintext)
            if verbose:
                print(f"Recovered block {i}: {result.plaintext!r}  (queries: {result.queries_used})")

        recovered = pkcs7_unpad(bytes(recovered_padded), BLOCK_SIZE)
        return recovered, per_block


class AeadSystem:
    """Comparison system using AES-GCM. There is no padding oracle to exploit."""

    def __init__(self, key: bytes | None = None):
        self.key = key or secrets.token_bytes(16)

    def encrypt(self, plaintext: bytes, associated_data: bytes = b"demo") -> bytes:
        nonce = secrets.token_bytes(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return nonce + tag + ciphertext

    def decrypt(self, blob: bytes, associated_data: bytes = b"demo") -> bytes:
        if len(blob) < 28:
            raise ValueError("Invalid AEAD blob length.")
        nonce = blob[:12]
        tag = blob[12:28]
        ciphertext = blob[28:]
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        cipher.update(associated_data)
        return cipher.decrypt_and_verify(ciphertext, tag)


def run_demo(message: bytes) -> None:
    print("=" * 72)
    print("CBC PADDING ORACLE DEMO")
    print("=" * 72)
    system = VulnerableCBCSystem()
    ciphertext = system.encrypt(message)

    print(f"Original plaintext: {message!r}")
    print(f"Ciphertext length (including IV): {len(ciphertext)} bytes")
    print()

    attacker = PaddingOracleAttacker(system)
    recovered, results = attacker.recover_plaintext(ciphertext, verbose=True)

    print()
    print("Final recovered plaintext:")
    print(recovered)
    print()
    print(f"Attack successful: {recovered == message}")
    print(f"Total oracle queries: {system.stats.queries}")
    if results:
        avg = system.stats.queries / len(results)
        print(f"Average oracle queries per recovered block: {avg:.2f}")

    print()
    print("=" * 72)
    print("AEAD COMPARISON (AES-GCM)")
    print("=" * 72)
    aead = AeadSystem()
    blob = aead.encrypt(message)
    tampered = bytearray(blob)
    tampered[-1] ^= 1
    try:
        _ = aead.decrypt(bytes(tampered))
        print("Unexpected result: tampered AEAD ciphertext was accepted.")
    except Exception as exc:  # broad on purpose for demo output clarity
        print("Tampered AES-GCM ciphertext rejected before any padding-style leakage occurs.")
        print(f"Decryption error type: {type(exc).__name__}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Educational CBC padding oracle demo.")
    parser.add_argument(
        "--message",
        type=str,
        default=(
            "CBC padding oracles show that confidentiality without integrity "
            "can fail under active attack."
        ),
        help="Plaintext message to encrypt and attack.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_demo(args.message.encode("utf-8"))


if __name__ == "__main__":
    main()
