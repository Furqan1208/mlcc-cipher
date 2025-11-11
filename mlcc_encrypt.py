# mlcc_encrypt.py

from mlcc_core import MLCCipher

def mlcc_encrypt(plaintext: str, substitution_key: str, vigenere_key: str, transposition_key: list) -> dict:
    """
    Encrypts plaintext using the MLCC algorithm.
    Returns a dictionary with success status and result or error.
    """
    try:
        cipher = MLCCipher(substitution_key, vigenere_key, transposition_key)
        result = cipher.encrypt(plaintext)
        return {
            "success": True,
            "ciphertext": result["ciphertext"],
            "intermediate_steps": result["intermediate_steps"]
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }
