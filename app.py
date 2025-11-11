# app.py

from flask import Flask, render_template, request, jsonify
import mlcc_encrypt
import mlcc_decrypt
import mlcc_keygen
import subprocess
import os
import tempfile
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    
    # --- FIX: Use camelCase keys to match the frontend ---
    plaintext = data.get('plaintext', '')
    substitution_key = data.get('substitutionKey', '')  # Changed from 'substitution_key'
    vigenere_key = data.get('vigenereKey', '')      # Changed from 'vigenere_key'
    transposition_key = data.get('transpositionKey', []) # Changed from 'transposition_key'
    # ----------------------------------------------------
    
    result = mlcc_encrypt.mlcc_encrypt(plaintext, substitution_key, vigenere_key, transposition_key)
    return jsonify(result)

@app.route('/api/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    
    # --- FIX: Use camelCase keys to match the frontend ---
    ciphertext = data.get('ciphertext', '')
    substitution_key = data.get('substitutionKey', '')  # Changed from 'substitution_key'
    vigenere_key = data.get('vigenereKey', '')      # Changed from 'vigenere_key'
    transposition_key = data.get('transpositionKey', []) # Changed from 'transposition_key'
    # ----------------------------------------------------
    
    result = mlcc_decrypt.mlcc_decrypt(ciphertext, substitution_key, vigenere_key, transposition_key)
    return jsonify(result)

@app.route('/api/keygen/substitution', methods=['GET'])
def get_substitution_key():
    key = mlcc_keygen.generate_substitution_key()
    return jsonify({"key": key})

@app.route('/api/keygen/vigenere', methods=['GET'])
def get_vigenere_key():
    key = mlcc_keygen.generate_vigenere_key()
    return jsonify({"key": key})

@app.route('/api/keygen/transposition', methods=['GET'])
def get_transposition_key():
    key = mlcc_keygen.generate_transposition_key()
    return jsonify({"key": key})

# ===== ATTACK TOOLS INTEGRATION =====

@app.route('/api/attack/frequency', methods=['POST'])
def frequency_analysis():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    
    if not ciphertext:
        return jsonify({"success": False, "error": "No ciphertext provided"})
    
    try:
        # Create temporary file with ciphertext
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write(ciphertext)
            temp_file = f.name
        
        # Run frequency analysis script
        result = subprocess.run([
            'python', 'attacks/frequency_analysis.py',
            '-i', temp_file,
            '--show-decode',
            '--sample-length', '200'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        # Clean up temp file
        os.unlink(temp_file)
        
        if result.returncode == 0:
            return jsonify({
                "success": True,
                "output": result.stdout,
                "analysis": parse_frequency_output(result.stdout)
            })
        else:
            return jsonify({
                "success": False,
                "error": result.stderr,
                "output": result.stdout
            })
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/attack/substitution', methods=['POST'])
def substitution_cracker():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    
    if not ciphertext:
        return jsonify({"success": False, "error": "No ciphertext provided"})
    
    try:
        # Run substitution cracker
        result = subprocess.run([
            'python', 'attacks/substitution_cracker.py',
            '-s', ciphertext,
            '--iterations', '1000',
            '--restarts', '10',
            '--sample-length', '200'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            return jsonify({
                "success": True,
                "output": result.stdout,
                "analysis": parse_substitution_output(result.stdout)
            })
        else:
            return jsonify({
                "success": False,
                "error": result.stderr,
                "output": result.stdout
            })
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

@app.route('/api/attack/transposition', methods=['POST'])
def transposition_bruteforce():
    data = request.get_json()
    ciphertext = data.get('ciphertext', '')
    
    if not ciphertext:
        return jsonify({"success": False, "error": "No ciphertext provided"})
    
    try:
        # Run transposition brute force
        result = subprocess.run([
            'python', 'attacks/transposition_bruteforce.py',
            '-s', ciphertext,
            '--max-keylen', '8',
            '--iterations', '500',
            '--restarts', '5',
            '--verbose'
        ], capture_output=True, text=True, cwd=os.getcwd())
        
        if result.returncode == 0:
            return jsonify({
                "success": True,
                "output": result.stdout,
                "analysis": parse_transposition_output(result.stdout)
            })
        else:
            return jsonify({
                "success": False,
                "error": result.stderr,
                "output": result.stdout
            })
            
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Helper functions to parse attack outputs
def parse_frequency_output(output):
    """Extract key information from frequency analysis output"""
    lines = output.split('\n')
    analysis = {
        "total_letters": 0,
        "top_letters": [],
        "suggested_mapping": {},
        "sample_decoded": ""
    }
    
    for i, line in enumerate(lines):
        if "Total letters" in line:
            analysis["total_letters"] = int(line.split(":")[1].strip())
        elif "SUGGESTED MAPPING" in line:
            # Parse mapping lines
            for j in range(i+2, min(i+30, len(lines))):
                if "->" in lines[j]:
                    parts = lines[j].split("->")
                    if len(parts) == 2:
                        cipher = parts[0].strip()
                        plain = parts[1].strip()
                        analysis["suggested_mapping"][cipher] = plain
                elif "SAMPLE DECODED" in lines[j]:
                    break
        elif "SAMPLE DECODED" in line:
            analysis["sample_decoded"] = lines[i+2] if i+2 < len(lines) else ""
    
    return analysis

def parse_substitution_output(output):
    """Extract key information from substitution cracker output"""
    lines = output.split('\n')
    analysis = {
        "recovered_key": "",
        "score": 0,
        "decoded_preview": ""
    }
    
    for i, line in enumerate(lines):
        if "Recovered key" in line and "(plain->cipher)" in line:
            analysis["recovered_key"] = lines[i+1].strip() if i+1 < len(lines) else ""
        elif "Score:" in line:
            try:
                analysis["score"] = float(line.split(":")[1].strip())
            except:
                pass
        elif "Decoded plaintext candidate" in line:
            analysis["decoded_preview"] = lines[i+2] if i+2 < len(lines) else ""
    
    return analysis

def parse_transposition_output(output):
    """Extract key information from transposition brute force output"""
    lines = output.split('\n')
    analysis = {
        "recovered_key_length": 0,
        "recovered_key_order": [],
        "score": 0,
        "plaintext_preview": ""
    }
    
    for i, line in enumerate(lines):
        if "Recovered key length:" in line:
            try:
                analysis["recovered_key_length"] = int(line.split(":")[1].strip())
            except:
                pass
        elif "Recovered key order:" in line:
            try:
                key_str = line.split(":")[1].strip().strip('[]')
                analysis["recovered_key_order"] = [int(x) for x in key_str.split(',')]
            except:
                pass
        elif "Score:" in line:
            try:
                analysis["score"] = float(line.split(":")[1].strip())
            except:
                pass
        elif "Plaintext preview:" in line:
            analysis["plaintext_preview"] = lines[i+1] if i+1 < len(lines) else ""
    
    return analysis

if __name__ == '__main__':
    app.run(debug=True)