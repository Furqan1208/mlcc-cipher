# mlcc_core.py

import math

class MLCCipher:
    """
    Multi-Layer Custom Cipher (MLCC) Core Implementation
    Combines substitution, modified Vigenère, and multi-directional transposition.
    """
    def __init__(self, substitution_key: str, vigenere_key: str, transposition_key: list):
        print(f"[MLCCipher DEBUG] __init__ called with: Sub='{substitution_key}' (len={len(substitution_key)}), Vig='{vigenere_key}', Trans={transposition_key}")
        if len(substitution_key) != 26 or len(set(substitution_key)) != 26:
            raise ValueError("Substitution key must be 26 unique characters")
        if len(vigenere_key) < 10:
            raise ValueError("Vigenère key must be at least 10 characters")
        if len(transposition_key) < 3:
            raise ValueError("Transposition key must have at least 3 elements")

        self.substitution_key = substitution_key.upper()
        self.vigenere_key = vigenere_key.upper()
        self.transposition_key = transposition_key

        standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        self.substitution_map = {standard_alphabet[i]: self.substitution_key[i] for i in range(26)}
        self.reverse_substitution_map = {self.substitution_key[i]: standard_alphabet[i] for i in range(26)}

    def encrypt(self, plaintext: str) -> dict:
        """
        Encrypts plaintext using the MLCC algorithm.
        Returns a dictionary with ciphertext and intermediate steps.
        """
        cleaned_text = ''.join(filter(str.isalpha, plaintext.upper()))

        substituted_text = ''.join(self.substitution_map[char] for char in cleaned_text)

        vigenere_result = ""
        key_rotation = 0

        for i, char in enumerate(substituted_text):
            effective_key = self.vigenere_key[(i + key_rotation) % len(self.vigenere_key)]
            
            shift = ord(effective_key) - ord('A')
            
            modifier = (i % 5) + 1
            encrypted_char = chr((ord(char) - ord('A') + shift * modifier) % 26 + ord('A'))
            vigenere_result += encrypted_char
            
            if (i + 1) % 5 == 0:
                key_rotation = (key_rotation + 1) % len(self.vigenere_key)

        num_columns = len(self.transposition_key)
        num_rows = math.ceil(len(vigenere_result) / num_columns)
        
        grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
        index = 0
        
        direction = 1  
        for row in range(num_rows):
            if direction == 1:
                for col in range(num_columns):
                    if index < len(vigenere_result):
                        grid[row][col] = vigenere_result[index]
                        index += 1
            else:
                for col in range(num_columns - 1, -1, -1):
                    if index < len(vigenere_result):
                        grid[row][col] = vigenere_result[index]
                        index += 1
            
            direction *= -1
        
        column_order = sorted(range(num_columns), key=lambda i: self.transposition_key[i])
        
        ciphertext = ""
        for col in column_order:
            for row in range(num_rows):
                if grid[row][col]:
                    ciphertext += grid[row][col]
        
        return {
            "ciphertext": ciphertext,
            "intermediate_steps": {
                "substituted_text": substituted_text,
                "vigenere_result": vigenere_result,
                "grid": grid,
                "column_order": column_order
            }
        }

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypts ciphertext using the MLCC algorithm.
        Returns the decrypted plaintext.
        """
        num_columns = len(self.transposition_key)
        L = len(ciphertext)
        num_rows = math.ceil(L / num_columns)
        
        column_order = sorted(range(num_columns), key=lambda i: self.transposition_key[i])
        
     
        total_grid_cells = num_rows * num_columns
        
        num_empty_cells = total_grid_cells - L
    
        last_row_index = num_rows - 1
        
        short_columns = []
        if num_empty_cells > 0:
            if last_row_index % 2 == 0:
                
                short_columns = list(range(num_columns - num_empty_cells, num_columns))
            else:
                short_columns = list(range(num_empty_cells))

       
        col_lengths = {}
        for col_index in range(num_columns):
            if col_index in short_columns:
                col_lengths[col_index] = num_rows - 1
            else:
                col_lengths[col_index] = num_rows
                
        grid = [['' for _ in range(num_columns)] for _ in range(num_rows)]
        
        index = 0
        for original_col_index in column_order:
            length = col_lengths[original_col_index]
            for row in range(length): 
                if index < L:
                    grid[row][original_col_index] = ciphertext[index]
                    index += 1
        
        vigenere_result = ""
        direction = 1  
        for row in range(num_rows):
            if direction == 1:
                for col in range(num_columns):
                    if grid[row][col]:
                        vigenere_result += grid[row][col]
            else:
                for col in range(num_columns - 1, -1, -1):
                    if grid[row][col]:
                        vigenere_result += grid[row][col]
            
            direction *= -1
        
        substituted_text = ""
        key_rotation = 0
        
        for i, char in enumerate(vigenere_result):
            effective_key = self.vigenere_key[(i + key_rotation) % len(self.vigenere_key)]
            
            shift = ord(effective_key) - ord('A')
            
            modifier = (i % 5) + 1
            decrypted_char = chr((ord(char) - ord('A') - shift * modifier + 26) % 26 + ord('A'))
            substituted_text += decrypted_char
            
            if (i + 1) % 5 == 0:
                key_rotation = (key_rotation + 1) % len(self.vigenere_key)
        
        cleaned_text = ''.join(self.reverse_substitution_map[char] for char in substituted_text)
        
        return cleaned_text