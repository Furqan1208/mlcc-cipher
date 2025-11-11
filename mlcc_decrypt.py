# mlcc_decrypt.py

from mlcc_core import MLCCipher

def mlcc_decrypt(ciphertext: str, substitution_key: str, vigenere_key: str, transposition_key: list) -> dict:
    """
    Decrypts ciphertext using the MLCC algorithm.
    Returns a dictionary with success status and result or error.
    """
    try:
        cipher = MLCCipher(substitution_key, vigenere_key, transposition_key)
        plaintext = cipher.decrypt(ciphertext)
        return {
            "success": True,
            "plaintext": plaintext
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
