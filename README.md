# FilesCrypterSavior
This is a GUI program based on Python3 which helps you encrypt and decrypt files and folders with AES-EAX or AES-GCM.

![image](https://user-images.githubusercontent.com/59511698/123561803-44e66600-d7b3-11eb-9d57-47cf7d6320f8.png)



### Tested On
- Windows 10 (Python 3.8.0/3.8.8/3.8.10 and exe)
- Windows 8.1 (exe)
- Parrot Linux (Python 3.9.1)

## Warning
FCS Version 3.0+ does not support Database files from previous versions. So you may keep the FCS V2.X and decrypt the files you have already encrypted, or just put manually keys and nonces in FCS newest version (Make sure you have selected `AES-EAX` encryption mode.)

## Preparation
- Download the project: `git clone https://github.com/JimChr-R4GN4R/FilesCrypterSavior`
- Try to run `FCSx64.exe` . If it does not open properly, then follow these steps to run it with python3:
- Make sure you support Python 3.X (in case .exe file is not running).
- Then install all required packages by typing in terminal (or cmd):
`python3 -m pip install -r requirements.txt`
- Then get in FilesCrypterSavior's folder and type:
`python3 FCS.py`
- Recommend to create a DB file via `DB settings` before start encrypting files.
- Done!


## Instructions
FCS Files:

![image](https://user-images.githubusercontent.com/59511698/123560523-5f1c4600-d7ab-11eb-86be-0232961d1424.png)

FCS Main Window:

(If encrypt key input is empty, it will be randomly generated)

![image](https://user-images.githubusercontent.com/59511698/123560662-58420300-d7ac-11eb-9c79-0a6953080d4c.png)

If you load a file, if no key entered, it will be automaticcaly generated.

FCS Menu (I recommend you to keep default options):

![image](https://user-images.githubusercontent.com/59511698/123560753-e1593a00-d7ac-11eb-8345-bf9eaa41faa2.png)
![image](https://user-images.githubusercontent.com/59511698/123560805-42810d80-d7ad-11eb-9540-1c811f960ae9.png)


## Presentation
[Presentation Video](https://www.youtube.com/watch?v=K3w5Q58m8UA) (Outdated)


## To-Do List
- [X] ~Add `Auto fill Key&Nonce` that checks if the file you want to decrypt exists in database, so it gets key and nonce and fills them in their input automatically.~

- [X] ~Add `Update Checker` option.~

- [X] ~Make save options feature.~

- [X] ~Added key uniqueness verification option.~

- [X] ~Make possible to choose more than one files at once and encrypt all of them automatically.~

- [ ] Add `BKP` (Basic Key Protector) system which means that user enters a key which he wants and database will be encrypted/decrypted by this key and files' keys and nonces will be generated automatically, so user has just to know only one key to encrypt/decrypt his files.



## Disclaimer
This is a beta version. There will be many updates. If you loose your keys/nonces, then you cannot recover the encrypted files. Your data, your responsibility.
