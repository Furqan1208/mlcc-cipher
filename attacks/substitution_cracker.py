#!/usr/bin/env python3
"""
attacks/substitution_cracker.py

Hill-climbing / simulated-annealing substitution cipher cracker.

Place this file in:
    CCP/attacks/substitution_cracker.py

Purpose:
 - Attempt to recover a monoalphabetic substitution key (plain->cipher format)
   by maximizing a heuristic English-language fitness score on the decoded text.

Usage examples:
    # basic run on ciphertext file
    python attacks/substitution_cracker.py -i data/cipher.txt --iterations 3000 --restarts 30

    # provide ciphertext directly
    python attacks/substitution_cracker.py -s "WKH TXLFN EURZQ ..." --iterations 2000 --restarts 10

    # save outputs
    python attacks/substitution_cracker.py -i data/cipher.txt -o attacks/recovered_key.txt --decoded attacks/decoded.txt --verbose

Notes about MLCC:
 - MLCC final ciphertext is transformed by substitution -> vigenere -> transposition.
 - This cracker targets substitution-only ciphertext (i.e., strings where substitution
   is the last stage before ciphertext). For MLCC use:
     * If you can undo transposition and Vigenere to get 'substituted_text' (vigenere_result),
       feed that to this tool for best results.
     * If you only have final ciphertext, run transposition brute-force first (attacks/transposition_bruteforce.py)
       and use its outputs as input to this script.
"""

from collections import Counter
import random
import math
import argparse
import sys
import os

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Common short words used to bias fitness towards English
COMMON_WORDS = ["THE","AND","THAT","HAVE","FOR","WITH","NOT","THIS","BUT","YOU","FROM","THEY","SAY","HER","SHE","WILL","ONE","ALL","WOULD","THERE","THEIR","WHAT","SO","UP","OUT","IF","ABOUT"]
# Common English digrams (good for scoring)
COMMON_DIGRAMS = ["TH","HE","IN","ER","AN","RE","ED","ON","ES","ST","EN","AT","TE","OR","TI","HI","AS","TE","ET","NG"]

def clean(text: str) -> str:
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def apply_key_plain_to_cipher(ciphertext: str, key_plain_to_cipher: str) -> str:
    """
    key_plain_to_cipher is a 26-char string: position 0 = substitution for 'A', position 1 for 'B', etc.
    mlcc_core uses that format to map plaintext->substituted letters (plain->cipher)
    For decoding (cipher -> plain), we invert the mapping.
    This function decodes ciphertext (which is currently in substituted alphabet) back to guessed plaintext.
    """
    # Build cipher->plain mapping
    inv = {}
    for i, plain_letter in enumerate(ALPHABET):
        cipher_letter = key_plain_to_cipher[i]
        inv[cipher_letter] = plain_letter
    # decode
    out = []
    for ch in ciphertext:
        if ch.isalpha():
            out.append(inv.get(ch, '?'))
        else:
            out.append(ch)
    return ''.join(out)

def score_text(pt: str) -> float:
    """Score plaintext candidate using simple heuristics: word hits + digram matches - penalty for ?"""
    s = 0.0
    up = pt.upper()
    # word bonus (heavier)
    for w in COMMON_WORDS:
        s += up.count(w) * 5.0
    # digram bonus (lighter)
    for dg in COMMON_DIGRAMS:
        s += up.count(dg) * 1.0
    # penalize unknowns / question marks from incomplete mapping
    s -= up.count('?') * 8.0
    # slightly reward length (avoid preferring very short)
    s += len(up) * 0.001
    return s

def random_key_plain_to_cipher(rng=random) -> str:
    letters = list(ALPHABET)
    rng.shuffle(letters)
    return ''.join(letters)

def perturb_key(key: str, rng=random) -> str:
    a = list(key)
    i, j = rng.sample(range(26), 2)
    a[i], a[j] = a[j], a[i]
    return ''.join(a)

def decode_with_key(ciphertext_clean: str, key_plain_to_cipher: str) -> str:
    return apply_key_plain_to_cipher(ciphertext_clean, key_plain_to_cipher)

def hillclimb(ciphertext: str, iterations=2000, restarts=20, rng_seed=None, verbose=False):
    """
    Hill-climbing with occasional simulated annealing acceptance.
    Returns best_key (plain->cipher), best_plain, best_score
    """
    if rng_seed is not None:
        rng = random.Random(rng_seed)
    else:
        rng = random.Random()

    text = clean(ciphertext)
    if not text:
        return None, "",  -1e9

    best_overall_key = None
    best_overall_score = -1e12
    best_overall_plain = ""

    for r in range(restarts):
        # initial key: random or frequency-based initial guess (we choose random for simplicity)
        current_key = random_key_plain_to_cipher(rng)
        current_plain = decode_with_key(text, current_key)
        current_score = score_text(current_plain)
        best_local_key = current_key
        best_local_score = current_score
        best_local_plain = current_plain

        # temperature schedule for SA-like acceptance
        T0 = 1.0
        for i in range(iterations):
            candidate_key = perturb_key(current_key, rng)
            candidate_plain = decode_with_key(text, candidate_key)
            candidate_score = score_text(candidate_plain)
            delta = candidate_score - current_score
            # acceptance
            if delta > 0 or math.exp(delta / max(1e-6, T0*(1 - i/iterations))) > rng.random():
                current_key = candidate_key
                current_plain = candidate_plain
                current_score = candidate_score
                if current_score > best_local_score:
                    best_local_score = current_score
                    best_local_key = current_key
                    best_local_plain = current_plain
            # (optional) small random restart inside a run
            if i % max(1, iterations//5) == 0 and rng.random() < 0.003:
                # small shake
                current_key = perturb_key(current_key, rng)
                current_plain = decode_with_key(text, current_key)
                current_score = score_text(current_plain)

        if verbose:
            print(f"[restart {r+1}/{restarts}] best_local_score={best_local_score:.2f}")

        if best_local_score > best_overall_score:
            best_overall_score = best_local_score
            best_overall_key = best_local_key
            best_overall_plain = best_local_plain

    return best_overall_key, best_overall_plain, best_overall_score

def key_plain_to_cipher_to_string(key: str) -> str:
    """Return key as 26-letter uppercase string (already in that format)."""
    return key.upper()

def save_decoded_and_key(key: str, decoded: str, key_path: str=None, decoded_path: str=None):
    if key_path:
        with open(key_path, 'w', encoding='utf-8') as f:
            f.write(key + "\n")
    if decoded_path:
        with open(decoded_path, 'w', encoding='utf-8') as f:
            f.write(decoded + "\n")

def main():
    parser = argparse.ArgumentParser(description="Substitution cipher cracker (hill-climbing) - outputs plain->cipher key string")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input-file', help="Ciphertext input file (will be cleaned to A-Z)")
    group.add_argument('-s', '--string', help="Ciphertext string directly")
    parser.add_argument('--iterations', type=int, default=3000, help="Iterations per restart (default 3000)")
    parser.add_argument('--restarts', type=int, default=30, help="Random restarts (default 30)")
    parser.add_argument('--seed', type=int, default=None, help="Random seed for reproducibility")
    parser.add_argument('--output-key', help="File to save recovered key (plain->cipher 26-letter string)")
    parser.add_argument('--decoded-out', help="File to save decoded plaintext candidate")
    parser.add_argument('--sample-length', type=int, default=600, help="Preview length of decoded output")
    parser.add_argument('--verbose', action='store_true', help="Verbose progress")
    parser.add_argument('--mode', choices=['auto','substitution_only'], default='substitution_only',
                        help="Mode: 'substitution_only' assumes input is substituted text (best). 'auto' will still try but may be worse on final MLCC ciphertext.")
    args = parser.parse_args()

    if args.input_file:
        if not os.path.exists(args.input_file):
            print(f"ERROR: input file not found: {args.input_file}", file=sys.stderr)
            sys.exit(2)
        raw = open(args.input_file, 'r', encoding='utf-8', errors='ignore').read()
    else:
        raw = args.string

    cleaned = clean(raw)
    if len(cleaned) == 0:
        print("No alphabetic content found in input.", file=sys.stderr)
        sys.exit(2)

    if args.verbose:
        print(f"[INFO] Running substitution cracker on input length {len(cleaned)} characters (cleaned).")
        print(f"[INFO] Iterations: {args.iterations}, Restarts: {args.restarts}, Seed: {args.seed}")

    best_key, best_plain, best_score = hillclimb(cleaned, iterations=args.iterations, restarts=args.restarts, rng_seed=args.seed, verbose=args.verbose)

    if best_key is None:
        print("Failed to recover key.", file=sys.stderr)
        sys.exit(1)

    # best_plain is the decoded candidate (cipher->plain using recovered key)
    # But mlcc_core expects key as plain->cipher mapping string.
    recovered_key_plain_to_cipher = key_plain_to_cipher_to_string(best_key)

    print("\n=== BEST RESULT ===")
    print("Recovered key (plain->cipher) 26-letter string (suitable for mlcc_core substitution key):")
    print(recovered_key_plain_to_cipher)
    print(f"\nScore: {best_score:.2f}\n")
    print("Decoded plaintext candidate (preview):\n")
    print(best_plain[:args.sample_length])
    print("\n(Preview end)\n")

    # save outputs if requested
    if args.output_key or args.decoded_out:
        save_decoded_and_key(recovered_key_plain_to_cipher, best_plain, key_path=args.output_key, decoded_path=args.decoded_out)
        if args.output_key:
            print(f"[INFO] Saved recovered key to: {args.output_key}")
        if args.decoded_out:
            print(f"[INFO] Saved decoded plaintext to: {args.decoded_out}")

    # final note for user
    print("Note: This solver targets monoalphabetic substitution (single-stage).\n"
          "For MLCC pipeline, feed this script the 'vigenere_result' string (i.e., after undoing transposition and Vigenere),\n"
          "or feed it candidate outputs from transposition_bruteforce.py to find plausible candidates.\n")

if __name__ == "__main__":
    main()
