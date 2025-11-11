#!/usr/bin/env python3
"""
attacks/frequency_analysis.py

Frequency analysis helper for the MLCC project.

Place this file in your project at:
    CCP/attacks/frequency_analysis.py

Usage (examples):
    python attacks/frequency_analysis.py -i data/cipher.txt
    python attacks/frequency_analysis.py -s "WKH TXLFN EURZQ IRA MXPSV RYHU WKH ODCB GRJ" --show-decode
    python attacks/frequency_analysis.py -i data/cipher.txt --output-mapping attacks/suggested_map.txt --json

What it does:
 - cleans ciphertext (letters only) by default
 - prints letter counts and relative frequencies (descending)
 - prints ASCII histogram bars
 - suggests a mapping (cipher -> guessed plaintext) by matching freq order to English letter frequency order
 - prints sample decoded text using the suggested mapping (first N chars)
 - can save mapping to disk (plain or json)

Notes:
 - This is a heuristic suggestion only. For multi-stage ciphers (like MLCC),
   frequency analysis on the final ciphertext might be weak because of
   substitution+vigenere+transposition. Use this as a first step, or run it
   on intermediate stage strings (vigenere_result) which your mlcc_core can return.
"""

from collections import Counter, OrderedDict
import argparse
import json
import sys
import os

# Standard English letters sorted by frequency (high -> low).
ENGLISH_FREQ_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"

def load_text_from_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()

def clean_text(text: str, keep_nonalpha=False) -> str:
    if keep_nonalpha:
        return text
    return ''.join(ch for ch in text.upper() if ch.isalpha())

def frequency_table(text: str) -> OrderedDict:
    """
    Returns an OrderedDict mapping letters -> (count, relative_frequency)
    Sorted descending by count.
    """
    text = clean_text(text)
    total = len(text)
    counts = Counter(text)
    # include letters with zero count as well, optionally:
    letters = sorted(counts.items(), key=lambda kv: -kv[1])
    freq = OrderedDict()
    for ch, cnt in letters:
        freq[ch] = (cnt, cnt / total if total > 0 else 0.0)
    return freq, total

def ascii_bar(pct: float, width: int = 40) -> str:
    # simple ASCII bar
    filled = int(round(pct * width))
    if filled < 0: filled = 0
    if filled > width: filled = width
    return '#' * filled + '-' * (width - filled)

def suggest_mapping_by_frequency(ciphertext: str) -> dict:
    """
    Suggests a cipher->plaintext mapping by aligning ciphertext letter frequency
    ranking with ENGLISH_FREQ_ORDER. Returns dict cipher_letter->plain_letter.
    Only letters present in ciphertext will be suggested; others left unmapped.
    """
    cleaned = clean_text(ciphertext)
    counts = Counter(cleaned)
    cipher_by_freq = [ch for ch, _ in counts.most_common()]
    suggestion = {}
    for i, ch in enumerate(cipher_by_freq):
        if i < len(ENGLISH_FREQ_ORDER):
            suggestion[ch] = ENGLISH_FREQ_ORDER[i]
        else:
            suggestion[ch] = '?'
    return suggestion

def apply_mapping_to_text(text: str, mapping: dict, placeholder: str = '?') -> str:
    """Apply cipher->plain mapping to text (letters only); non-alpha preserved optional by providing already-cleaned text."""
    out = []
    text_upper = text.upper()
    for ch in text_upper:
        if ch.isalpha():
            out.append(mapping.get(ch, placeholder))
        else:
            # preserve original character (space, punctuation) for readability
            out.append(ch)
    return ''.join(out)

def save_mapping(mapping: dict, path: str, as_json: bool = False):
    if as_json:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(mapping, f, indent=2)
    else:
        with open(path, 'w', encoding='utf-8') as f:
            for c, p in sorted(mapping.items()):
                f.write(f"{c} -> {p}\n")

def print_frequency_report(freq_dict: OrderedDict, total: int, show_top: int = None):
    print(f"Total letters (A-Z) counted: {total}")
    header = f"{'Letter':6s} | {'Count':6s} | {'Freq':6s} | {'Bar'}"
    print(header)
    print('-' * len(header))
    items = list(freq_dict.items())
    if show_top:
        items = items[:show_top]
    for ch, (cnt, rel) in items:
        print(f"{ch:6s} | {cnt:6d} | {rel:6.4f} | {ascii_bar(rel)}")

def main():
    parser = argparse.ArgumentParser(description="Frequency analysis helper for MLCC project")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-i', '--input-file', help="Path to ciphertext file")
    group.add_argument('-s', '--string', help="Ciphertext string directly")
    parser.add_argument('--keep-nonalpha', action='store_true', help="Do not strip non-alpha characters (useful for previewing spacing/punct)")
    parser.add_argument('--show-decode', action='store_true', help="Show sample decoded text using suggested mapping")
    parser.add_argument('--sample-length', type=int, default=400, help="Length of sample decoded text to show")
    parser.add_argument('--output-mapping', help="Path to save suggested mapping (plain text)")
    parser.add_argument('--json', action='store_true', help="If set with --output-mapping save mapping as JSON")
    parser.add_argument('--top', type=int, default=None, help="Show only top N letters in frequency table")
    parser.add_argument('--no-guess', action='store_true', help="Do not produce suggested mapping (just show frequencies)")
    args = parser.parse_args()

    # load text
    if args.input_file:
        if not os.path.exists(args.input_file):
            print(f"ERROR: input file not found: {args.input_file}", file=sys.stderr)
            sys.exit(2)
        raw = load_text_from_file(args.input_file)
    else:
        raw = args.string

    cleaned = clean_text(raw, keep_nonalpha=args.keep_nonalpha)
    freq_dict, total = frequency_table(cleaned)

    # print report
    print("\n=== FREQUENCY REPORT ===\n")
    if total == 0:
        print("No alphabetic characters found in input. Check your file/string.")
        sys.exit(0)
    print_frequency_report(freq_dict, total, show_top=args.top)

    if not args.no_guess:
        suggestion = suggest_mapping_by_frequency(cleaned)
        print("\n=== SUGGESTED MAPPING (cipher -> guess plaintext) ===\n")
        # print mapping sorted by cipher letter
        for c in sorted(suggestion.keys()):
            print(f"  {c} -> {suggestion[c]}")
        if args.output_mapping:
            save_mapping(suggestion, args.output_mapping, as_json=args.json)
            print(f"\nSaved suggested mapping to: {args.output_mapping}")

        if args.show_decode:
            sample = cleaned[:args.sample_length]
            decoded_sample = apply_mapping_to_text(sample, suggestion, placeholder='?')
            print("\n=== SAMPLE DECODED (using suggested mapping) ===\n")
            # show original sample (preserve a bit of spacing from raw if not cleaning)
            print(decoded_sample)
            print("\n\nNote: This decoding is heuristic. For MLCC final ciphertext this may be weak.\n"
                  "Consider running this on intermediate output (vigenere_result) from mlcc_core if available.\n")

if __name__ == "__main__":
    main()
