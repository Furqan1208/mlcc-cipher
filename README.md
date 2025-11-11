
<div align="center">

[![License](https://img.shields.io/github/license/Furqan1208/mlcc-cipher)](LICENSE)

<img width="471" height="467" alt="MLCC Cipher Logo" src="https://github.com/user-attachments/assets/afba3371-5212-4490-b2c6-23c90e55bfe5" />

</div>

# MLCC Cipher — Multi-Layer Custom Cipher

**MLCC Cipher** is a Python-based multi-layer encryption system combining classical cryptographic techniques for enhanced security:
- Substitution Cipher
- Modified Vigenère Cipher (with positional modifier)
- Multi-directional Transposition Cipher

This repository contains:
- Core Python modules (`mlcc_core.py`, `mlcc_encrypt.py`, `mlcc_decrypt.py`, `mlcc_keygen.py`)
- Flask-based web interface (`app.py`, `templates/index.html`)
- Attack and analysis tools (`attacks/`)
- Documentation and screenshots

---

## Quickstart

### 1. Clone the repository
```bash
git clone https://github.com/Furqan1208/mlcc-cipher.git
cd mlcc-cipher
```
### 2. Create and activate a virtual environment
**Windows**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**Linux/macOS**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Flask application
**Windows**
```bash
set FLASK_APP=app.py
flask run
```

**Linux/macOS**
```bash
export FLASK_APP=app.py
flask run
```
**Open http://127.0.0.1:5000/ in your browser.**

---

## Directory Structure
```bash
mlcc-cipher/
├── app.py
├── mlcc_core.py
├── mlcc_encrypt.py
├── mlcc_decrypt.py
├── mlcc_keygen.py
├── templates/
│   └── index.html
├── attacks/
│   ├── frequency_analysis.py
│   ├── substitution_cracker.py
│   ├── transposition_bruteforce.py
│   └── vigenere_cracker.py
├── requirements.txt
├── LICENSE
├── README.md
└── figures/  
```

---

## Contributing

Contributions are welcome! Please fork the repo, create a branch, and submit a pull request.

---

## Demo / Screenshots

- **Main Dashboard**  
<img width="1914" height="897" alt="image" src="https://github.com/user-attachments/assets/f41d9771-61e4-47e7-b209-2a843c380dc1" />


- **Encrypt Message Screen**  
<img width="1917" height="877" alt="image" src="https://github.com/user-attachments/assets/7099d8ef-b6c7-4169-9a8e-0a624d3fa5b3" />


- **Decrypt Message Screen**  
<img width="1912" height="880" alt="image" src="https://github.com/user-attachments/assets/6bdfae24-8c35-43eb-be16-a5e6cf1bae94" />


- **Visualize Encryption Screen**  
<img width="1913" height="873" alt="image" src="https://github.com/user-attachments/assets/49808709-fd70-420d-aa3f-b116ab3f324d" />


- **Security Analysis Screen**  
<img width="1907" height="877" alt="image" src="https://github.com/user-attachments/assets/c54bcd99-70ed-4d5b-beb0-830e122858cd" />


- **Attack Tools Screen**  
<img width="1914" height="862" alt="image" src="https://github.com/user-attachments/assets/b0f167a0-b4b7-45d0-b735-cf8c2b7c6072" />

---

## License

This project is licensed under the terms in the included LICENSE file.
