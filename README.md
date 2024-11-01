
# Advanced File Encryption App

This is a Python-based file encryption application with a graphical interface designed using Tkinter, offering robust encryption methods for both individual files and entire directories. Users can choose between AES and Fernet encryption techniques to protect sensitive files, with a sleek design and an intuitive user experience.


## Features

- AES and Fernet Encryption Methods: Secure files and folders using AES and Fernet encryption, with options to choose preferred methods.
- Password-Protected Access: Encrypt and decrypt files with password-protected access to ensure only authorized users can open them.
- File and Folder Support: Easily encrypt/decrypt individual files or entire folders with a single click.
- Intuitive GUI: User-friendly interface with customizable themes, including light and dark mode.
- Custom Icons and Branding: Custom button icons and logo with rounded edges, enhancing visual appeal.
- Cross-Platform Compatibility: Works on multiple operating systems, including Windows, macOS, and Linux.

- Error Handling and Validation: Provides clear feedback and error messages, such as "Nice Try!! Better luck next time" for incorrect decryption passwords.
- Encryption/Decryption Logs: Maintains a log file of encryption and decryption actions, including file paths and timestamps.








## Screenshots

[App Screenshot 1](https://prnt.sc/zgRpsKjK75oN)

[App Screenshot 2](https://prnt.sc/4qXcgwEVkIsP)


## Requirements
- Python 3.8+
- Required packages (Install via pip):
  - tkinter
  - cryptography
  - Pillow
## Installation

 1.Clone the repository:

```python
git clone https://github.com/RedwanHaasaan/advanced-file-encryption-app.git
cd advanced-file-encryption-app
```
2.Install dependencies:
```python
pip install -r requirements.txt

```
3.Run the application:
```Python
python encryption_decryption.py

```
## Usage/Examples

```
1.Launch the app and select a file or folder to encrypt or decrypt.

2.Choose an encryption method: AES or Fernet.

3.Enter a password and click the desired action (Encrypt or Decrypt).

4.The app confirms success, and for Fernet, the encryption key file is managed automatically.
```


## Contributing

Contributions are always welcome!

Feel free to open issues or submit pull requests with improvements. All contributions are welcome!

