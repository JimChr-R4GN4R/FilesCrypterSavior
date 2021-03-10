FCS_Version = 'V1.9' # DON'T REMOVE OR MOVE THIS LINE

from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from tkinter import scrolledtext 
from PIL import Image, ImageTk
import os
from os import path
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
import logging
import pyperclip
import hashlib
import shutil
import mmap


###--- Methods ---###


def UpdateCheck():
	import requests
	
	Logger('info',"Checking for new version...")

	try:
		
		try:
			last_version = int ( requests.get("https://raw.githubusercontent.com/JimChr-R4GN4R/FilesCrypterSavior/main/FilesCrypterSavior.py").text.split('\n')[0].split(' ')[2].replace("'","").replace('V','').replace('.','').replace('\r','') )
			cur_version = int( FCS_Version[1:].replace('.','') )
				
			if last_version > cur_version:
				Logger('info',"There is a newer version! Please update FCS.")
			else:
				Logger('info',"You are up to date.")
		except ValueError:
			Logger('error',"Please check back later or contact with R4GN4R. Probably there is an update on the way!")


	except requests.exceptions.RequestException:
		Logger('error',"[UC-1] Please check your internet connection.")
	except requests.exceptions.HTTPError:
		Logger('error',"[UC-2] Http Error.")
	except requests.exceptions.ConnectionError:
		Logger('error',"[UC-3] Error Connecting.")
	except requests.exceptions.Timeout:
		Logger('error',"[UC-4] Timeout Error.")   


def Logger(mtype, message):
	Logging_window.configure(state='normal') # Enable Logging window to add messages
	if mtype == 'warn':
		message = '[Warning] - ' + message
	elif mtype =='info':
		message = '[Info] - ' + message
	elif mtype =='imp':
		message = '[Important] - ' + message
	elif mtype =='error':
		message = '[Error] - ' + message
	message += '\n'

	Logging_window.insert(INSERT, message)
	Logging_window.configure(state='disabled')# Disable Logging window to not edit messages


def KeyRandomGenerator():
	key_input_encrypt.delete(0,END)
	key = get_random_bytes(ChangeKeyGenBits.keybytes).hex()
	key_input_label_encrypt['text'] = "Key (Hex):"
	key_input_encrypt.insert(0,key)
	pyperclip.copy(key) # Copy hex key to clickboard
	Logger('info',"Key has been copied in your clickboard.")


def ChangeKeyGenBits(event):

	if '128bits' in AES_encrypt_random_key_generator_button['text']:
		AES_encrypt_random_key_generator_button['text'] = 'Generate 192bits Key (Hex)'
		ChangeKeyGenBits.keybytes = 192//8
	elif '192bits' in AES_encrypt_random_key_generator_button['text']:
		AES_encrypt_random_key_generator_button['text'] = 'Generate 256bits Key (Hex)'
		ChangeKeyGenBits.keybytes = 256//8
	else:
		AES_encrypt_random_key_generator_button['text'] = 'Generate 128bits Key (Hex)'
		ChangeKeyGenBits.keybytes = 128//8


def EncryptKeyBytesHexFormat(event=None):
	if "Hex" in key_input_label_encrypt['text']:
		if len(key_input_encrypt.get()) > 32:
			key_input_encrypt.delete(32,END)
			messagebox.showerror("Key's Length Error", "This key hex value should not be more than 32 bytes.\nLength has been fixed")
			key_input_label_encrypt['text'] = "Key (Bts):"
		else:
			key_input_label_encrypt['text'] = "Key (Bts):"
	else:
		if len(key_input_encrypt.get()) > 32:
			messagebox.showerror("Key's Length Error", "Your key should not be more than 32 bytes.\nLength has been fixed")
			key_input_encrypt.delete(32,END)
			key_input_label_encrypt['text'] = "Key (Hex):"
		else:
			key_input_label_encrypt['text'] = "Key (Hex):"


def DecryptKeyBytesHexFormat(event=None):
	if "Hex" in key_input_label_decrypt['text']:
		if len(key_input_decrypt.get()) > 32:
			key_input_decrypt.delete(32,END)
			messagebox.showerror("Key's Length Error", "This key hex value should not be more than 32 bytes.\nLength has been fixed")
			key_input_label_decrypt['text'] = "Key (Bts):"
		else:
			key_input_label_decrypt['text'] = "Key (Bts):"
	else:
		if len(key_input_decrypt.get()) > 32:
			messagebox.showerror("Key's Length Error", "Your key should not be more than 32 bytes.\nLength has been fixed")
			key_input_decrypt.delete(32,END)
			key_input_label_decrypt['text'] = "Key (Hex):"
		else:
			key_input_label_decrypt['text'] = "Key (Hex):"


def Data_Encrypt(key): # Encrypt Data
	try:
		cipher = AES.new(key, AES.MODE_EAX)
		nonce = cipher.nonce ; Logger( 'imp',"Nonce (hex): " + nonce.hex() ) # sign nonce
		Logger('info',"Encrypting with AES-EAX...")
		try:
			enc_bytes = cipher.encrypt( pad(LoadFile.data,16) ) # Fix file bytes length | Encrypting...
			if Load_file_in_ram_value == 1:
				with open(LoadFile.filepath + '.fcsenc', 'wb') as enc_file:
					enc_file = mmap.mmap(enc_file.fileno(), 0, access=mmap.ACCESS_WRITE)
					enc_file.write(enc_bytes)
				enc_file.close()

			else:
				enc_file = open(LoadFile.filepath + '.fcsenc', 'wb') # Make new enc_file
				enc_file.write(enc_bytes) # Write encrypted bytes in enc_file 
				enc_file.close()
		except MemoryError:
			Logger('error',"[DE-3] File could not be encrypted, cause of not enough memory. (Encryption Stopped)")
			return

		if Delete_original_file_checkbox_value.get():
			try:
				os.remove(LoadFile.filepath) # delete original file
			except PermissionError:
				Logger('error', "[DE-0] FCS does not have permission to delete original folder. (Encryption Continues)")

		enc_file_hash = hashlib.sha256(enc_bytes).hexdigest()

		if Backup_keyFile_value.get(): # Option Backup key and nonce to file_keys_backup.txt enabled
			with open('file_keys_backup.txt', 'a') as enc_file:
				try:
					if '(Bts)' in key_input_label_encrypt['text']:
						enc_file.write(LoadFile.filepath + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Bts): "+unpad(key,16).decode('utf-8') + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					else:
						enc_file.write(LoadFile.filepath + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Hex): " + key.hex() + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					Logger('info',"Key/Nonce have been added in the database.")
				except UnicodeEncodeError: # If LoadFile.filepath has unicodes like \u202a, remove them and save decoded filename in db
					file = "".join([char for char in LoadFile.filepath if ord(char) < 128])
					if '(Bts)' in key_input_label_encrypt['text']:
						enc_file.write(file + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Bts): "+unpad(key,16).decode('utf-8') + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					else:
						enc_file.write(file + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Hex): " + key.hex() + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					Logger('info',"Key/Nonce have been added in the database.")
				except Exception as e:
					Logger('error',"[DE-2] There was an error occured when tried to save key and nonce in databse. Please copy them and save them by hand in a safe place.")
					print(e) # For debug purpose


		Logger('info',"Encryption Finished.")
		Load_Button['text'] = "Load File/Folder"
		
	except ValueError:
		Logger('error',"[DE-1] Encryption Failed. Please check your key's length and value")


def AES_Encrypt(): # AES Encrypt

	if Load_Button['text'] == "Load File/Folder":
		Logger('warn',"Please select a file to encrypt.")
		return


	elif path.exists(LoadFile.filepath): # file exists

		if Load_Type.get() == 1: # If folder has been selected
			if FolderToZip():
				return


		key = key_input_encrypt.get()

		if len(key) > 0:

			if "Hex" in key_input_label_encrypt['text']:

				try:
					key = bytes.fromhex(key)

				except ValueError:
					Logger('warn',"Key's hex value is incorrect.")
					return

			else:
				key = pad(key.encode(),16)

			Data_Encrypt(key)

		else:
			
			Logger('warn',"Please add a key.")
	else:
		Logger('error',"[AE-1] File doesn't exist.")


def AES_Decrypt(): # AES Decrypt

	if Load_Button['text'] == "Load File/Folder":
		Logger('warn',"Please select a file to decrypt.")

	elif path.exists(LoadFile.filepath): # file exists
		key = key_input_decrypt.get()
		nonce = Nonce_input_decrypt.get()

		if len(key) > 0 and len(nonce) > 0:

			if 'Hex' in key_input_label_decrypt['text']:

				try: # unhex key
					key = bytes.fromhex(key)
				except ValueError:
					Logger('error',"[AD-1] Key's hex value is incorrect.")
					return
			else:
				key = pad(key.encode(),16)

			try: # unhex nonce
				nonce = bytes.fromhex(nonce)
			except ValueError:
				Logger('error',"[AD-2] Nonce's hex value is incorrect.")
				return
			
			if len(key) > 32:
				Logger('warn',"Your key must not be more than 32 bytes.")
				return

			try:
				cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
				Logger('info',"Decrypting with AES-EAX...")

				try:
					decrypted_filename = LoadFile.filepath[:-7] # remove .fcsenc extension
					dec_bytes = unpad(cipher.decrypt(LoadFile.data),16)
					dec_file = open(decrypted_filename, 'wb')
					dec_file.write(dec_bytes)
					dec_file.close()
					os.remove(LoadFile.filepath) # Delete encrypted file and backup_keys
					Logger('info',"Decryption Finished.")

					if decrypted_filename[-14:] == '.fcsfolder.zip': # if decrypted file has this extension, then it's zipped folder
						shutil.unpack_archive(decrypted_filename, decrypted_filename[:-14], 'zip' ) # unzip
						os.remove(decrypted_filename) # delete zip file


					Load_Button['text'] = "Load File/Folder"

					try: # If key and nonce are saved in database, then after decryption, delete specific line
						with open('file_keys_backup.txt','r') as f:
							tmp = ''
							for i in f.readlines():
								if LoadFile.filepath not in i:
									tmp += i
						with open('file_keys_backup.txt','w') as f:
							f.write(tmp)
					except FileNotFoundError:
						Logger('info',"There wasn't found any key/nonce database to remove specific information. (Not Important)")

				except ValueError:
					Logger('error',"[AD-3] Key or Nonce is not correct.")

			except ValueError:
				Logger('error',"[AD-4] Key or Nonce is not correct.")

		else:
			Logger('warn',"Please fill Key and Nonce.")

	else:
		Logger('error',"[AD-5] File doesn't exist.")


def FileReader(file):
		Logger('info',"Loading file data. Please wait...")

		if Load_file_in_ram_value == 1:
			with open(file, 'rb') as f:
				LoadFile.data = ( mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) ).read()
		else:
			try:
				LoadFile.data = open(file, 'rb').read() # import data from file.txt
			except FileNotFoundError:
				Logger('error',"[FR-1] File wasn't found. (Encryption/Decryption Stopped)")
				return
			except MemoryError:
				if FolderToZip.compression_finished_verification_var != -1:
					Logger('error',"[FR-2] Zipped file could not be read, cause of not enough memory. (Encryption Stopped)")
					if FolderToZip.compression_finished_verification_var == 0:
						Logger('info',"Please make some space and encrypt the zip file manually.")
				else:
					Logger('error',"[FR-3] File could not be read, cause of not enough memory. (Encryption Stopped)")

		if LoadFile.name_filename[-7:] == '.fcsenc': # If the file is encrypted, then check the database if it's recorded
			QuickDecryptChecker()

		if len(LoadFile.full_filename_path) > 47:
			LoadFile.full_filename_path = LoadFile.full_filename_path[:25]+".../..."+LoadFile.full_filename_path[len(LoadFile.full_filename_path)-20:]

		Load_Button['text'] = LoadFile.full_filename_path # Update LoadFile Button text with loaded file path



def FolderToZip():
	FolderToZip.compression_finished_verification_var = -1

	Logger('info',"Folder compression is about to start. Please wait...")
	try:
		Logger('info', "Compressing folder in zip format...")
		shutil.make_archive(LoadFile.filepath + '.fcsfolder', 'zip', LoadFile.filepath)
		Logger('info', "Compression Finished.")
		FolderToZip.compression_finished_verification_var = 0
	except FileNotFoundError:
		Logger( 'error', "There is no folder with that address: '{}' (Encryption Stopped)".format(LoadFile.filepath) )
		FolderToZip.compression_finished_verification_var = 1
		return 1

	try:
		os.remove(LoadFile.filepath) # Delete original folder which got compressed
	except PermissionError:
		Logger('error', "[FTZ-0] FCS does not have permission to delete original folder. (Encryption Continues)")

	LoadFile.filepath = LoadFile.filepath + '.fcsfolder.zip'
	FileReader(LoadFile.filepath)


def LoadFile():

	if Load_Type.get() == 1: # Load_Type is folder
		LoadFile.Load_folder_addr = filedialog.askdirectory(title="Select A Folder")
		if LoadFile.Load_folder_addr:
			LoadFile.addr_filename, LoadFile.name_filename = os.path.split(LoadFile.Load_folder_addr) # address of directories | filename.*
			LoadFile.full_filename_path = LoadFile.addr_filename + "/" + LoadFile.name_filename # example/test/file.txt
			LoadFile.filepath = os.path.join(LoadFile.addr_filename, LoadFile.name_filename) # fix filepath format
			if len(LoadFile.full_filename_path) > 47:
				LoadFile.full_filename_path = LoadFile.full_filename_path[:25]+".../..."+LoadFile.full_filename_path[len(LoadFile.full_filename_path)-20:]

			Load_Button['text'] = LoadFile.full_filename_path # Update LoadFile Button text with loaded file path

	else: # Load_Type is file

		LoadFile.Load_filename_addr = filedialog.askopenfilename(title="Select A File", filetypes=[("All Files", "*.*")] )

		if LoadFile.Load_filename_addr: # If user has selected a file
			LoadFile.addr_filename, LoadFile.name_filename = os.path.split(LoadFile.Load_filename_addr) # address of directories | filename.*
			LoadFile.full_filename_path = LoadFile.addr_filename + "/" + LoadFile.name_filename # example/test/file.txt
			LoadFile.filepath = os.path.join(LoadFile.addr_filename, LoadFile.name_filename) # fix filepath format

			FileReader(LoadFile.filepath)





def QuickDecryptChecker(): # Check if encrypted file is in database

	
	if path.exists('file_keys_backup.txt'):
		file_hash = hashlib.sha256(LoadFile.data).hexdigest()

		with open('file_keys_backup.txt','r') as f:
			for line in f.readlines():
				if file_hash in line:
					Logger('info',"This file has been found in the database, so key and nonce have been filled automatically.")
					file_items = line.split(' | ')
					key = (file_items[2])[11:] # key value
					nonce = (file_items[3])[13:-1] # nonce value

					if (file_items[2])[:9] == 'Key (Hex)': # if key's format is Hex, then change it in program's settings
						key_input_label_decrypt['text'] = "Key (Hex):"
					else:
						key_input_label_decrypt['text'] = "Key (Bts):"

					key_input_decrypt.delete(0,END) # clear decrypt key input
					key_input_decrypt.insert(0,key) # fill decrypt key input with key value
					Nonce_input_decrypt.delete(0,END) # clear nonce input
					Nonce_input_decrypt.insert(0,nonce) # fill nonce input with nonce value
					break



###___ Methods ___###




gui = Tk(className='FilesCrypterSavior ' + FCS_Version + '.')
gui.geometry("1000x480")
gui.resizable(False,False)




###--- Default Values ---###
ChangeKeyGenBits.keybytes = 128//8 # Default generate key bytes length
LoadFile.filepath = "-" # Default filepath which does not exist
###___ Default Values ___###


####--- Menu Options ---####

menubar = Menu(gui)
view_menu = Menu(menubar)

###--- Option 0 ---###
view_menu.add_command(label="Check for updates", command=UpdateCheck)
###___ Option 0 ___###

###--- Option 1 ---###
Delete_original_file_checkbox_value = IntVar(value=1)
view_menu.add_checkbutton(label="Delete original file after encryption/decryption", onvalue=1, offvalue=0, variable=Delete_original_file_checkbox_value)
###___ Option 1 ___###

###--- Option 2 ---###
Backup_keyFile_value = IntVar(value=1)
view_menu.add_checkbutton(label="Add key and nonce in the database", onvalue=1, offvalue=0, variable=Backup_keyFile_value)
###___ Option 2 ___###

###--- Option 3 ---###
Load_file_in_ram_value = IntVar(value=0)
view_menu.add_checkbutton(label="Load file in RAM", onvalue=1, offvalue=0, variable=Load_file_in_ram_value)
###___ Option 3 ___###

menubar.add_cascade(label='Options', menu=view_menu)
gui.config(menu=menubar)

####___ Menu Options ___####


row_num = 0
###--- Logo ---###
photo = PhotoImage(file = "logo.png")
gui.iconphoto(False, photo)
logo_img  = Image.open("Letters_logo.png") # logo
img=ImageTk.PhotoImage(logo_img)
lab=Label(image=img).grid(row=row_num, columnspan=2, sticky=W)
###___ Logo ___###


row_num += 2
###--- Load Button ---###
Load_Button = Button(gui, text="Load File/Folder", height=2, width=65, command=LoadFile)
Load_Button.grid(row=row_num,column=0,columnspan=2, pady=5, sticky=W)
###___ Load Button ___###


###--- Load Options ---###
Load_Type = IntVar()
R1 = Radiobutton(gui, text="File", variable=Load_Type, value=0)
R1.grid(row=row_num,column=1, sticky=E, ipadx=20)
R2 = Radiobutton(gui, text="Folder", variable=Load_Type, value=1)
R2.grid(row=row_num,column=2, sticky=W)
###___ Load Options ___###


row_num += 1
####--- AES Encrypt ---####


###--- Key Input ---###
key_input_label_encrypt = Label(gui, text="Key (Bts):")
key_input_label_encrypt.grid(row=row_num, column=0, sticky='W')
key_input_label_encrypt.bind('<Button-1>',EncryptKeyBytesHexFormat)
key_input_encrypt = Entry(gui, width=70, borderwidth=1)
key_input_encrypt.grid(row=row_num, column=1, padx=5, pady=40)
###___ Key Input ___###

###--- Generate Key Button ---###
AES_encrypt_random_key_generator_button = Button(gui, text ="Generate 128bits Key (Hex)", height=2, padx=5, fg="green2", bg="black", command=KeyRandomGenerator)
AES_encrypt_random_key_generator_button.grid(row=row_num, column=2, rowspan=2, sticky=W)
AES_encrypt_random_key_generator_button.bind("<Button-3>", ChangeKeyGenBits)
###___ Generate Key Button ___###

AES_encrypt_button = Button(gui, text ="AES Encrypt", height=2, padx=5, fg="green2", bg="black", command=AES_Encrypt).grid(row=row_num, column=3, rowspan=2, sticky=W) #AES Encrypt Button


####___ AES Encrypt ___####





row_num += 2
####--- AES Decrypt ---####


###--- Key Input ---###
key_input_label_decrypt = Label(gui, text="Key (Hex):")
key_input_label_decrypt.grid(row=row_num, column=0, sticky='W')
key_input_decrypt = Entry(gui, width=70, borderwidth=1)
key_input_decrypt.grid(row=row_num, column=1, padx=15)
key_input_label_decrypt.bind('<Button-1>',DecryptKeyBytesHexFormat)
###___ Key Input ___###

###--- Nonce Input ---###
Nonce_input_label = Label(gui, text="Nonce (Hex):", anchor=W).grid(row=row_num+1, column=0)
Nonce_input_decrypt = Entry(gui, width=70, borderwidth=1)
Nonce_input_decrypt.grid(row=row_num+1, column=1, padx=5)
###___ Nonce Input ___###

AES_decrypt_button = Button(gui, text ="AES Decrypt", height=2, padx=5, fg="green2", bg="black", command=AES_Decrypt).grid(row=row_num, column=2, rowspan=2, sticky=W) # AES Decrypt Button


####___ AES Decrypt ___####


row_num += 2
###--- Logger ---###
log_label = Label(gui, text="Log:", anchor=W).grid(row=row_num, column=0, pady=15, sticky='W')
Logging_window = scrolledtext.ScrolledText(gui, width = 100, height = 10)
Logging_window.grid(row=row_num, column=1, columnspan=4, pady=15)
###___ Logger ___###



gui.mainloop()
