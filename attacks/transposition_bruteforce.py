#!/usr/bin/env python3
"""
attacks/transposition_bruteforce.py

Brute-force / heuristic solver for columnar transposition ciphers.

Place this file in:
    CCP/attacks/transposition_bruteforce.py

Purpose:
 - Tries to recover transposition key length and ordering by scoring outputs
   with English-likeness metrics.

Usage examples:
    python attacks/transposition_bruteforce.py -i data/cipher.txt --max-keylen 10
    python attacks/transposition_bruteforce.py -s "CEHSIR..." --max-keylen 12 --verbose
    python attacks/transposition_bruteforce.py -i data/cipher.txt --save-best decoded_transpo.txt

Notes about MLCC:
 - The MLCC ciphertext is processed by substitution -> vigenere -> transposition.
 - This attack targets the **final transposition layer**.
 - Feed this script the "vigenere_result" (after undoing substitution and vigenere) for optimal results.
"""

import itertools
import math
import argparse
import random
import os
import sys

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
COMMON_WORDS = ["THE","AND","ING","ION","ENT","HER","FOR","THA","NTH","HES","HIS","ERE","TIO","VER","ALL","WAS","YOU"]

def clean(text: str) -> str:
    """Keep only alphabetic characters."""
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def columnar_decrypt(cipher: str, key_order: list[int]) -> str:
    """
    Perform columnar transposition decryption given a key order.
    key_order: e.g. [2,0,1] means col2, col0, col1 is the reading order.
    """
    n_cols = len(key_order)
    n_rows = math.ceil(len(cipher) / n_cols)
    # Compute approximate column lengths
    full_cols = len(cipher) % n_cols
    col_lengths = [n_rows if i < full_cols else n_rows - 1 for i in range(n_cols)]

    # Fill columns in ciphertext order
    cols = []
    index = 0
    for pos in range(n_cols):
        col_len = col_lengths[key_order.index(pos)]
        cols.append(list(cipher[index:index+col_len]))
        index += col_len

    # Rebuild plaintext row-wise
    plaintext = []
    for r in range(n_rows):
        for c in range(n_cols):
            if r < len(cols[c]):
                plaintext.append(cols[c][r])
    return ''.join(plaintext)

def score_text(text: str) -> float:
    """Simple English-likeness score."""
    score = 0.0
    up = text.upper()
    for w in COMMON_WORDS:
        score += up.count(w) * 4.0
    score += sum(ch in "ETAOINSHRDLU" for ch in up) * 0.2
    return score / max(1, len(text))

def random_key(n_cols, rng=random):
    key = list(range(n_cols))
    rng.shuffle(key)
    return key

def hillclimb_transposition(cipher, keylen, iterations=3000, restarts=10, rng_seed=None, verbose=False):
    """Heuristic hill-climbing approach to reorder columns for best English score."""
    rng = random.Random(rng_seed)
    best_key = None
    best_score = -1e9
    best_plain = ""

    for r in range(restarts):
        current_key = random_key(keylen, rng)
        current_plain = columnar_decrypt(cipher, current_key)
        current_score = score_text(current_plain)

        for i in range(iterations):
            a, b = rng.sample(range(keylen), 2)
            new_key = current_key[:]
            new_key[a], new_key[b] = new_key[b], new_key[a]
            new_plain = columnar_decrypt(cipher, new_key)
            new_score = score_text(new_plain)

            if new_score > current_score or math.exp((new_score - current_score) / max(1e-6, 1 - i/iterations)) > rng.random():
                current_key, current_score, current_plain = new_key, new_score, new_plain

            if current_score > best_score:
                best_score = current_score
                best_key = current_key
                best_plain = current_plain

        if verbose:
            print(f"[Restart {r+1}/{restarts}] Best local score = {best_score:.4f}")

    return best_key, best_plain, best_score

def brute_force_lengths(cipher, min_len=3, max_len=10, iterations=1500, restarts=5, verbose=False):
    """Try multiple key lengths to find best-scoring decryption."""
    cleaned = clean(cipher)
    best_len, best_score, best_plain, best_key = None, -1e9, "", None

    for L in range(min_len, max_len + 1):
        if verbose:
            print(f"\n[INFO] Trying key length = {L}")
        key, plain, score = hillclimb_transposition(cleaned, L, iterations, restarts, verbose=verbose)
        if score > best_score:
            best_score, best_plain, best_key, best_len = score, plain, key, L

    return best_len, best_key, best_plain, best_score

def save_result(plaintext, key_order, path):
    with open(path, "w", encoding="utf-8") as f:
        f.write("Recovered Key Order: " + str(key_order) + "\n")
        f.write("Plaintext:\n" + plaintext)
    print(f"[INFO] Saved best result to {path}")

def main():
    parser = argparse.ArgumentParser(description="Transposition cipher brute-force/hill-climb cracker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-i", "--input-file", help="Input ciphertext file")
    group.add_argument("-s", "--string", help="Ciphertext as direct string")
    parser.add_argument("--min-keylen", type=int, default=3)
    parser.add_argument("--max-keylen", type=int, default=10)
    parser.add_argument("--iterations", type=int, default=3000)
    parser.add_argument("--restarts", type=int, default=10)
    parser.add_argument("--seed", type=int, default=None)
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--save-best", help="Path to save best result")
    args = parser.parse_args()

    if args.input_file:
        if not os.path.exists(args.input_file):
            print(f"ERROR: File not found: {args.input_file}")
            sys.exit(2)
        ciphertext = open(args.input_file, "r", encoding="utf-8", errors="ignore").read()
    else:
        ciphertext = args.string

    cleaned = clean(ciphertext)
    if not cleaned:
        print("No valid alphabetic content found.", file=sys.stderr)
        sys.exit(2)

    if args.verbose:
        print(f"[INFO] Input length: {len(cleaned)}")
        print(f"[INFO] Trying key lengths from {args.min_keylen} to {args.max_keylen}")

    best_len, best_key, best_plain, best_score = brute_force_lengths(
        cleaned,
        min_len=args.min_keylen,
        max_len=args.max_keylen,
        iterations=args.iterations,
        restarts=args.restarts,
        verbose=args.verbose
    )

    print("\n=== BEST RESULT ===")
    print(f"Recovered key length: {best_len}")
    print(f"Recovered key order: {best_key}")
    print(f"Score: {best_score:.4f}")
    print("\nPlaintext preview:\n")
    print(best_plain[:600])
    print("\n(Preview end)\n")

    if args.save_best:
        save_result(best_plain, best_key, args.save_best)

    print("Note: This solver targets **transposition-only** ciphertext.\n"
          "For MLCC, run this before substitution_cracker.py to guess correct column ordering.\n")

if __name__ == "__main__":
    main()
