
# Manual Encrypt

A simple Python application that utilizes [`tkinter`](https://en.wikipedia.org/wiki/Tkinter) for the graphical user interface (GUI) and [`cryptography`](https://cryptography.io/en/latest/) for secure key exchange, data encryption, and decryption. The application employs the following cryptographic protocols:

- **Key Exchange Protocol**: [ECDH (Elliptic-Curve Diffie-Hellman)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) using the [`X25519`](https://en.wikipedia.org/wiki/Curve25519) curve for secure and efficient key exchange.
- **Encryption and Authentication**: [AES-256-GCM](https://en.wikipedia.org/wiki/Galois/Counter_Mode) (Advanced Encryption Standard in Galois/Counter Mode) for robust encryption with integrity and authentication via tags.


---

## Prerequisites

Before running or compiling the project, ensure the following are installed:

- **Python**: Version 3.6 or higher
- **Pip**: Python's package manager
- **Dependencies**:
  - `cryptography`
  - `tkinter` (bundled with Python)

Install required Python packages using:
```bash
pip install cryptography
```

For Windows compilation:
- **PyInstaller**: To install PyInstaller, run:
  ```bash
  pip install pyinstaller
  ```

---

## Running the Project

### 1. Clone the Repository
```bash
git clone https://github.com/tingfeifeng/manual_encrypt.git
cd manual_encrypt
```

### 2. Run the Script
Run the Python script manually from the terminal:
```bash
python main.py
```

---

## Compiling to `.exe` for Windows

### 1. Install PyInstaller
Ensure PyInstaller is installed:
```bash
pip install pyinstaller
```

### 2. Create the Executable
Run the following command to compile the script into a standalone `.exe`:
```bash
pyinstaller --onefile --windowed main.py
```

#### Explanation of Options:
- `--onefile`: Bundles everything into a single `.exe` file.
- `--windowed`: Excludes the terminal/console window (useful for GUI applications).

This will create the `.exe` file in the `dist` directory.

### 3. Run the Executable
Navigate to the `dist` directory and double-click the generated `.exe` file to launch your application.

---
## Troubleshooting

### Common Issues
1. **`ModuleNotFoundError: No module named 'cryptography'`**
   - Ensure the module is installed:
     ```bash
     pip install cryptography
     ```

2. **PyInstaller Missing Libraries**
   - If the `.exe` doesn't work as expected, ensure all dependencies are installed and accessible. You can run:
     ```bash
     pyinstaller --onefile --windowed main.py --clean
     ```
     The `--clean` flag ensures a fresh build.
3. **Permission Issues**
   - If permissions are denied, try running the commands with administrator privileges.
---

