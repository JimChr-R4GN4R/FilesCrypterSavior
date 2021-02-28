# FilesCrypterSavior
This is a GUI program based on Python3 which helps you encrypt and decrypt data with AES-GCM.

### Tested On
- Windows 10 with Python 3.8.8


## Preparation
- Make sure you support Python 3.X .
- Download the project: `git clone https://github.com/JimChr-R4GN4R/FilesCrypterSavior`
- Then install all required packages by typing in terminal (or cmd):
`python3 -m pip install -r requirements.txt`


- Then get in FilesCrypterSavior's folder and type:
`python3 FilesCrypterSavior.py`

- Done!

## Presentation
[Presentation Video](https://www.youtube.com/watch?v=K3w5Q58m8UA)


## To-Do List
- [ ] Add `Auto fill Key&Nonce` that checks if the file you want to decrypt exists in database, so it gets key and nonce and fills them in their input automatically.
- [ ] Add `BKP` (Basic Key Protector) system which means that user enters a key which he wants and database will be encrypted/decrypted by this key and files' keys and nonces will be generated automatically, so user has just to know only one key to encrypt/decrypt his files.
- [ ] When selecting a folder instead of file, zip it and then encrypt it
- [ ] Add `Update Checker` option.
