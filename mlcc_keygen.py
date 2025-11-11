# mlcc_keygen.py

import random
import string

def generate_substitution_key() -> str:
    """
    Generates a random 26-character substitution key.
    Returns a shuffled uppercase alphabet.
    """
    alphabet = string.ascii_uppercase
    shuffled_alphabet = random.sample(alphabet, len(alphabet))
    return "".join(shuffled_alphabet)

def generate_vigenere_key(min_length=10, max_length=20) -> str:
    """
    Generates a random Vigenère key.
    Returns a string of random uppercase letters of a random length.
    """
    length = random.randint(min_length, max_length)
    return "".join(random.choices(string.ascii_uppercase, k=length))

def generate_transposition_key(min_length=3, max_length=6) -> str:
    """
    Generates a random transposition key.
    Returns a comma-separated string of unique integers.
    """
    length = random.randint(min_length, max_length)
    # Generate a list of numbers from 1 to length and shuffle it
    key_numbers = random.sample(range(1, length + 1), length)
    return ",".join(map(str, key_numbers))
