#!/usr/bin/env python3
"""
attacks/vigenere_cracker.py

Recover MLCC's modified Vigenere key from aligned pre- and post-Vigenere strings.

Place in:
    CCP/attacks/vigenere_cracker.py

Usage examples (aligned known-pair mode):
    # provide both strings directly
    python attacks/vigenere_cracker.py -a "SUBSTITUTEDTEXT..." -b "VIGENERERESULT..." --min-keylen 5 --max-keylen 15

    # provide as files
    python attacks/vigenere_cracker.py -A substituted.txt -B vigenere.txt --keylen 12

What this does:
 - Supports MLCC's modified Vigenere:
     effective_key_index for position i = (i + floor(i/5)) % keylen
     modifier at position i = (i % 5) + 1
     encryption: c_i = (s_i + shift_k * modifier_i) mod 26
 - For a given key length L, groups positions by effective_key_index and
   derives the possible numeric shifts (0..25) consistent with every occurrence
   in that group. Intersects possibilities across occurrences to find
   consistent shifts.
 - If every group has at least one candidate, prints candidate keys (caps to a reasonable count).
 - If groups are ambiguous (more than one candidate), the script can enumerate combinations
   up to a limit (default 200) — useful to feed into other crackers.

Notes:
 - This script *requires* aligned strings (substituted_text and vigenere_result).
   You can get those from mlcc_core.encrypt(...)'s intermediate_steps, or by undoing the transposition layer first.
"""

import argparse
import os
import sys
import itertools

ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_MAP = {c: i for i, c in enumerate(ALPHABET)}
INV_ALPHABET_MAP = {i: c for c, i in ALPHABET_MAP.items()}


def clean_alpha(s: str) -> str:
    return ''.join(ch for ch in s.upper() if ch.isalpha())


def pos_to_key_index(i: int, keylen: int) -> int:
    # key_rotation = floor(i / 5)
    # effective index = (i + key_rotation) % keylen
    return (i + (i // 5)) % keylen


def modifier_for_pos(i: int) -> int:
    return (i % 5) + 1


def possible_shifts_for_pair(sub_ch: str, vig_ch: str, modifier: int):
    """
    Solve: vig = sub + s * modifier  (mod 26)
    For s in 0..25, return all s satisfying the congruence.
    """
    if sub_ch not in ALPHABET_MAP or vig_ch not in ALPHABET_MAP:
        return []
    s_sub = ALPHABET_MAP[sub_ch]
    s_vig = ALPHABET_MAP[vig_ch]
    possible = []
    for s in range(26):
        if (s_sub + (s * modifier)) % 26 == s_vig:
            possible.append(s)
    return possible


def derive_candidates_for_keylen(substituted: str, vigenere_result: str, keylen: int, max_combinations=200):
    n = len(substituted)
    # Initialize candidate sets for each key index
    candidates = [set(range(26)) for _ in range(keylen)]

    for i in range(n):
        p = pos_to_key_index(i, keylen)
        modifier = modifier_for_pos(i)
        sub_ch = substituted[i]
        vig_ch = vigenere_result[i]
        poss = possible_shifts_for_pair(sub_ch, vig_ch, modifier)
        if not poss:
            # no solution for this pair -> keylen impossible
            return None
        # intersect
        candidates[p] &= set(poss)
        if len(candidates[p]) == 0:
            return None

    # Prepare enumeration info
    candidate_lists = [sorted(list(c)) for c in candidates]
    total_comb = 1
    for lst in candidate_lists:
        total_comb *= max(1, len(lst))
        if total_comb > max_combinations:
            break

    if total_comb == 0:
        return None

    keys = []
    if total_comb <= max_combinations:
        # enumerate all combinations
        for combo in itertools.product(*candidate_lists):
            # convert numeric shifts to letters (shift -> letter with value shift)
            key_letters = ''.join(INV_ALPHABET_MAP[s] for s in combo)
            keys.append((combo, key_letters))
    else:
        # too many combinations; return summarized result only
        keys = None

    return {
        "keylen": keylen,
        "per_position_candidates": candidate_lists,
        "enumerated_keys": keys,
        "estimated_combinations": total_comb
    }


def solve_by_trying_keylens(substituted: str, vigenere_result: str, min_len: int = 3, max_len: int = 20, max_enum=200):
    results = []
    for L in range(min_len, max_len + 1):
        res = derive_candidates_for_keylen(substituted, vigenere_result, L, max_combinations=max_enum)
        if res is None:
            continue
        results.append(res)
    return results


def print_result_block(res):
    print(f"\n=== Candidate key length: {res['keylen']} ===")
    per_pos = res['per_position_candidates']
    for idx, cand in enumerate(per_pos):
        letters = ''.join(INV_ALPHABET_MAP[s] for s in cand)
        print(f" pos {idx:2d}: possible numeric shifts {sorted(cand)} -> letters [{letters}]")
    print(f"Estimated total combinations: {res['estimated_combinations']}")
    if res['enumerated_keys'] is not None:
        print("\nEnumerated candidate keys:")
        for combo, keystr in res['enumerated_keys']:
            print(f"  key shifts {combo} -> key letters: {keystr}")


def main():
    parser = argparse.ArgumentParser(description="Recover MLCC modified-Vigenere key from aligned pre/post strings")
    # Accept either direct strings or files (both required in some form)
    parser.add_argument("-A", "--sub-file", help="File containing substituted_text (pre-Vigenere)")
    parser.add_argument("-B", "--vig-file", help="File containing vigenere_result (post-Vigenere)")
    parser.add_argument("-a", "--sub-string", help="substituted_text directly as string")
    parser.add_argument("-b", "--vig-string", help="vigenere_result directly as string")
    parser.add_argument("--min-keylen", type=int, default=3)
    parser.add_argument("--max-keylen", type=int, default=20)
    parser.add_argument("--max-enumerate", type=int, default=200, help="Maximum key combinations to enumerate per length")
    parser.add_argument("--clean", action="store_true", help="Strip non-alpha characters before processing")
    args = parser.parse_args()

    # Validate that we have one of file/string for substituted and one of file/string for vigenere
    if not (args.sub_file or args.sub_string):
        print("Provide substituted string via --sub-string or --sub-file", file=sys.stderr)
        sys.exit(2)
    if not (args.vig_file or args.vig_string):
        print("Provide vigenere result via --vig-string or --vig-file", file=sys.stderr)
        sys.exit(2)

    # load inputs
    if args.sub_file:
        if not os.path.exists(args.sub_file):
            print("Substituted file not found.", file=sys.stderr)
            sys.exit(2)
        sub_raw = open(args.sub_file, "r", encoding="utf-8", errors="ignore").read()
    else:
        sub_raw = args.sub_string

    if args.vig_file:
        if not os.path.exists(args.vig_file):
            print("Vigenere file not found.", file=sys.stderr)
            sys.exit(2)
        vig_raw = open(args.vig_file, "r", encoding="utf-8", errors="ignore").read()
    else:
        vig_raw = args.vig_string

    if args.clean:
        substituted = clean_alpha(sub_raw)
        vigenere_result = clean_alpha(vig_raw)
    else:
        substituted = ''.join(ch for ch in sub_raw.upper() if ch.isalpha())
        vigenere_result = ''.join(ch for ch in vig_raw.upper() if ch.isalpha())

    if len(substituted) != len(vigenere_result):
        print("Length mismatch after cleaning/alignment. Make sure strings are aligned and same length.", file=sys.stderr)
        print(f"len(substituted)={len(substituted)}, len(vigenere_result)={len(vigenere_result)}", file=sys.stderr)
        sys.exit(2)

    if len(substituted) == 0:
        print("No alphabetic content found after cleaning.", file=sys.stderr)
        sys.exit(2)

    print(f"[INFO] Input length: {len(substituted)}. Trying key lengths {args.min_keylen}..{args.max_keylen}")

    results = solve_by_trying_keylens(substituted, vigenere_result, min_len=args.min_keylen, max_len=args.max_keylen, max_enum=args.max_enumerate)

    if not results:
        print("No consistent key length found in the given range.")
        sys.exit(0)

    for res in results:
        print_result_block(res)

    print("\nDone. If multiple candidate keys were enumerated, try them by decrypting substituted_text with")
    print("the candidate key and passing result through your substitution_cracker (or compare to known plaintext).")
    print("If some positions have multiple possibilities, reduce combinations by using a known-plaintext slice or")
    print("by testing the best few combos against an English scoring function.\n")


if __name__ == "__main__":
    main()
