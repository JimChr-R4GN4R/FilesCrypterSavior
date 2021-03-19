# FilesCrypterSavior
This is a GUI program based on Python3 which helps you encrypt and decrypt files and folders with AES-EAX.
![image](https://user-images.githubusercontent.com/59511698/110950390-76463d80-834c-11eb-87c3-3d1cf2b72d1e.png)


### Tested On
- Windows 10 with Python 3.8.8
- Parrot Linux with Python 3.9.1


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
- [X] ~Add `Auto fill Key&Nonce` that checks if the file you want to decrypt exists in database, so it gets key and nonce and fills them in their input automatically.~


- [X] ~Add `Update Checker` option.~


- [X] ~When selecting a folder instead of file, zip it and then encrypt it.~ (It's recommended not to encrypt files more than ~3GB at once if there is not enough space and RAM)

- [X] ~Make save options feature.~

- [ ] ~Add option that you can load data directly to RAM instead of hard disk in case there is not enough disk space.~ (Not stable)

- [Χ] ~Added key uniqueness verification option.~

- [ ] Add `BKP` (Basic Key Protector) system which means that user enters a key which he wants and database will be encrypted/decrypted by this key and files' keys and nonces will be generated automatically, so user has just to know only one key to encrypt/decrypt his files.

