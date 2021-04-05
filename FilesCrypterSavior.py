FCS_Version = 'V2.7' # DON'T REMOVE OR MOVE THIS LINE

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
from sys import platform


ERRORS = {
	'[UC-0]':"Please check back later or contact with R4GN4R. Probably there is an update on the way!",
	'[UC-1]':"Please check your internet connection.",
	'[UC-2]':"HTTP Error.",
	'[UC-3]':"Error Connecting.",
	'[UC-4]':"Timeout Error.",
	'[KRG-0]':"Keys backup file was not found to check if generated key is already in use.",
	'[DE-0]':"FCS does not have permission to delete original folder. (Encryption Continues)",
	'[DE-1]':"Encryption Failed. Please check your key's length and value.",
	'[DE-2]':"There was an error occured when tried to save key and nonce in databse. Please copy them and save them by hand in a safe place.",
	'[DE-3]':"File could not be encrypted, cause of not enough memory. (Encryption Stopped)",
	'[DE-4]':"There is no file with this name.",
	'[AE-1]':"File doesn't exist.",
	'[AD-1]':"Key's hex value is incorrect.",
	'[AD-2]':"Nonce's hex value is incorrect.",
	'[AD-3]':"Key or Nonce is not correct.",
	'[AD-4]':"Key or Nonce is not correct.",
	'[AD-5]':"File doesn't exist.",
	'[FR-1]':"File wasn't found. (Encryption/Decryption Stopped)",
	'[FR-2]':"Zipped file could not be read, cause of not enough memory. (Encryption Stopped)",
	'[FR-3]':"File could not be read, cause of not enough memory. (Encryption Stopped)",
	'[FTZ-0]':"FCS does not have permission to delete original folder. (Encryption Continues)",
	'[FTZ-1]':"There is no folder with this address. (Encryption Stopped)"
}


###--- Methods ---###


def DefaultSettingsSetter():
	ChangeKeyGenBits.keybytes = 256//8 # Default generate key bytes length
	LoadFile.filepath = "-" # Default filepath which does not exist

	global Delete_original_file_checkbox_value
	global Backup_key_nonce_setting_value
	global Load_file_in_ram_value
	global Keys_Backup_file
	global Generated_key_in_use_checker_value


	Delete_original_file_checkbox_value = IntVar(value=1)
	Backup_key_nonce_setting_value = IntVar(value=1)
	Load_file_in_ram_value = IntVar(value=0)
	Keys_Backup_file = 'file_keys_backup.txt' # Default file
	Generated_key_in_use_checker_value = IntVar(value=1)

	try:
		settings_file = open('settings.txt').readlines()
		for line in settings_file:
			try:
				option_name, value = line.replace('\n','').split(' :=: ')
				if option_name == 'Delete_original_file_checkbox_value': Delete_original_file_checkbox_value = IntVar(value=int(value))
				elif option_name == 'Backup_key_nonce_setting_value': Backup_key_nonce_setting_value = IntVar(value=int(value))
				#elif option_name == 'Load_file_in_ram_value': Load_file_in_ram_value = IntVar(value=int(value))
				elif option_name == 'Keys_Backup_file': Keys_Backup_file = value
				elif option_name == 'Generated_key_in_use_checker_value': Generated_key_in_use_checker_value = IntVar(value=int(value))
			except:
				pass

	except FileNotFoundError:
		Logger('error',"settings.txt was not found. Default settings have been setted.")
		SettingsSave()


def SettingsSave():
	global Delete_original_file_checkbox_value
	global Backup_key_nonce_setting_value
	# global Load_file_in_ram_value
	global Keys_Backup_file
	global Generated_key_in_use_checker_value

	with open('settings.txt','w') as f:
		f.write('Delete_original_file_checkbox_value :=: ' + str(Delete_original_file_checkbox_value.get()) + '\n')
		f.write('Backup_key_nonce_setting_value :=: ' + str(Backup_key_nonce_setting_value.get()) + '\n')
		#f.write('Load_file_in_ram_value :=: ' + str(Load_file_in_ram_value.get()) + '\n') # Not used for now
		f.write('Keys_Backup_file :=: ' + Keys_Backup_file + '\n')
		f.write('Generated_key_in_use_checker_value :=: ' + str(Generated_key_in_use_checker_value.get()) )

	Logger('info',"Settings have been saved.")


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
			Logger('error',"[UC-0]")


	except requests.exceptions.RequestException:
		Logger('error',"[UC-1]")
	except requests.exceptions.HTTPError:
		Logger('error',"[UC-2]")
	except requests.exceptions.ConnectionError:
		Logger('error',"[UC-3]")
	except requests.exceptions.Timeout:
		Logger('error',"[UC-4]")   


def ImportKeysBackupFile():
	global Keys_Backup_file
	Keys_Backup_file = filedialog.askopenfilename(title="Select Key Backup file", filetypes=[("Text File", "*.txt")] )

	if Keys_Backup_file:
		Logger('info',f'You have selected as Keys Backup file: {Keys_Backup_file} \n(To be your default backup file, please Save Settings.)')
	else:
		Keys_Backup_file = 'file_keys_backup.txt'


def Logger(mtype, message):
	Logging_window.configure(state='normal') # Enable Logging window to add messages
	if mtype == 'warn':
		message = '[Warning] - ' + message
	elif mtype =='info':
		message = '[Info] - ' + message
	elif mtype =='imp':
		message = '[Important] - ' + message
	elif mtype =='error':
		message = '[Error] - ' + message + ' ' + ERRORS[message]
	message += '\n'

	Logging_window.insert(INSERT, message)
	Logging_window.configure(state='disabled') # Disable Logging window to not edit messages


def KeyRandomGenerator():
	global Keys_Backup_file
	global Generated_key_in_use_checker_value
	key_input_encrypt.delete(0,END)
	key = get_random_bytes(ChangeKeyGenBits.keybytes).hex()

	if Backup_key_nonce_setting_value.get() and Generated_key_in_use_checker_value.get(): # If key will be saved in backup file, check if key is already in use. 
		try:
			with open(Keys_Backup_file, 'r') as key_backup_file:
				while key in key_backup_file:
					key = get_random_bytes(ChangeKeyGenBits.keybytes).hex()
		except FileNotFoundError:
			Logger('error',"[KRG-0]")

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


def Data_Encrypt(filepath,key): # Encrypt Data
	try:
		cipher = AES.new(key, AES.MODE_EAX)
		nonce = cipher.nonce ; Logger( 'imp',"Nonce (hex): " + nonce.hex() ) # sign nonce
		Logger('info',"Encrypting with AES-EAX...")
		try:
			Data_Encrypt.enc_bytes = cipher.encrypt( pad(FileReader.data,16) ) # Fix file bytes length | Encrypting...
			FileReader.data = None
			if Load_file_in_ram_value == 1:
				try:
					WriteFileFromRAM(filepath + '.fcsenc')
				except ValueError:
					Logger('error',"[DE-4]")
					return

			else:
				enc_file = open(filepath + '.fcsenc', 'wb') # Make new enc_file
				enc_file.write(Data_Encrypt.enc_bytes) # Write encrypted bytes in enc_file 
				enc_file.close()
		except MemoryError:
			Logger('error',"[DE-3]")
			return

		if Delete_original_file_checkbox_value.get():
			try:
				os.remove(filepath) # delete original file
				Logger('info',"Original file has been deleted.")
			except PermissionError:
				Logger('error', "[DE-0]")

		enc_file_hash = FileSha256Hasher(Data_Encrypt.enc_bytes)

		if Backup_key_nonce_setting_value.get(): # Option Backup key and nonce to file_keys_backup.txt enabled
			with open(Keys_Backup_file, 'a') as key_backup_file:
				try:
					if '(Bts)' in key_input_label_encrypt['text']:
						key_backup_file.write(filepath + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Bts): "+unpad(key,16).decode('utf-8') + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					else:
						key_backup_file.write(filepath + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Hex): " + key.hex() + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					Logger('info',"Key/Nonce have been added in the Keys Backup file.")
				except UnicodeEncodeError: # If filepath has unicodes like \u202a, remove them and save decoded filename in db
					file = "".join([char for char in filepath if ord(char) < 128])
					if '(Bts)' in key_input_label_encrypt['text']:
						key_backup_file.write(file + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Bts): "+unpad(key,16).decode('utf-8') + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					else:
						key_backup_file.write(file + '.fcsenc' + ' | Hash256: ' + enc_file_hash + " | Key (Hex): " + key.hex() + " | " + "Nonce (Hex): " + nonce.hex() + '\n')
					Logger('info',"Key/Nonce have been added in the Keys Backup file.")
				except Exception as e:
					Logger('error',"[DE-2]")
					print(e) # For debug purpose


		Logger('info',"Encryption Finished.")
		Load_Button['text'] = "Load File/Folder"
		
	except Exception as e:
		Logger('error',"[DE-1]")
		print(e)
		print(key)

	Data_Encrypt.enc_bytes = None


def AES_Encrypt(): # AES Encrypt

	if Load_Button['text'] == "Load File/Folder":
		Logger('warn',"Please select a file to encrypt.")
		return


	elif R1['text'] == 'File':
		if path.exists(LoadFile.filepath): # file exists
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
				Data_Encrypt(LoadFile.filepath,key)
			else:
				Logger('warn',"Please add a key.")
		else:
			Logger('error',"[AE-1]")


def AES_Decrypt(): # AES Decrypt

	if Load_Button['text'] == "Load File/Folder":
		Logger('warn',"Please select a file to decrypt.")

	elif path.exists(LoadFile.filepath): # file exists
		FileSha256Hasher(FileReader.data)
		key = key_input_decrypt.get()
		nonce = Nonce_input_decrypt.get()

		if len(key) > 0 and len(nonce) > 0:

			if 'Hex' in key_input_label_decrypt['text']:

				try: # unhex key
					key = bytes.fromhex(key)
				except ValueError:
					Logger('error',"[AD-1]")
					return
			else:
				key = pad(key.encode(),16)

			try: # unhex nonce
				nonce = bytes.fromhex(nonce)
			except ValueError:
				Logger('error',"[AD-2]")
				return
			
			if len(key) > 32:
				Logger('warn',"Your key must not be more than 32 bytes.")
				return

			try:
				cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
				Logger('info',"Decrypting with AES-EAX...")

				try:
					decrypted_filename = LoadFile.filepath[:-7] # remove .fcsenc extension
					dec_bytes = unpad(cipher.decrypt(FileReader.data),16)
					dec_file = open(decrypted_filename, 'wb')
					dec_file.write(dec_bytes)
					dec_file.close()
					os.remove(LoadFile.filepath) # Delete encrypted file and backup_keys
					Logger('info',"Original file has been deleted.")
					Logger('info',"Decryption Finished.")

					if decrypted_filename[-14:] == '.fcsfolder.zip': # if decrypted file has this extension, then it's zipped folder
						shutil.unpack_archive(decrypted_filename, decrypted_filename[:-14], 'zip' ) # unzip
						os.remove(decrypted_filename) # delete zip file
						Logger('info',"Original file has been deleted.")


					Load_Button['text'] = "Load File/Folder"

					try: # If key and nonce are saved in Keys Backup file, then after decryption, delete specific line
						with open(Keys_Backup_file,'r') as f:
							tmp = ''
							for i in f.readlines():
								if LoadFile.filepath not in i:
									tmp += i
						with open(Keys_Backup_file,'w') as f:
							f.write(tmp)
					except FileNotFoundError:
						Logger('info',"There wasn't found any key/nonce Keys Backup file to remove specific information. (Not Important)")

				except ValueError:
					Logger('error',"[AD-3]")

			except ValueError:
				Logger('error',"[AD-4]")

		else:
			Logger('warn',"Please fill Key and Nonce.")

	else:
		Logger('error',"[AD-5]")


def FileReader(file):
		Logger('info',"Loading file data. Please wait...")

		if Load_file_in_ram_value == 1:
			try:
				LoadFileToRAM(file)
			except ValueError:
				Logger('error',"[FR-0] There is no file with this name.")
				return
		else:
			try:
				FileReader.data = open(file, 'rb').read() # import data from file.txt
				FileReader.file_hash = FileSha256Hasher(FileReader.data) # get it's sha256
			except FileNotFoundError:
				Logger('error',"[FR-1]")
				return
			except MemoryError:
				if FolderToZip.compression_finished_verification_var != -1:
					Logger('error',"[FR-2]")
					return
					if FolderToZip.compression_finished_verification_var == 0:
						Logger('info',"Please make some space and encrypt the zip file manually.")
						return
				else:
					Logger('error',"[FR-3]")
					return

		Logger('info',"Loading Completed.")

		if LoadFile.name_filename[-7:] == '.fcsenc' and R1['text'] == 'File' : # If the file is encrypted, then check the Keys Backup file if it's saved
			QuickDecryptChecker(FileReader.file_hash)


def FolderToZip():
	FolderToZip.compression_finished_verification_var = -1

	Logger('info',"Folder compression is about to start. Please wait...")
	try:
		Logger('info', "Compressing folder in zip format...")
		shutil.make_archive(LoadFile.filepath + '.fcsfolder', 'zip', LoadFile.filepath)
		Logger('info', "Compression Finished.")
		FolderToZip.compression_finished_verification_var = 0
	except FileNotFoundError:
		Logger( 'error', f"[FTZ-1]")
		FolderToZip.compression_finished_verification_var = 1
		return 1

	try:
		os.remove(LoadFile.filepath) # Delete original folder which got compressed
		Logger('info',"Original file has been deleted.")
	except PermissionError:
		Logger('error', "[FTZ-0]")

	LoadFile.filepath = LoadFile.filepath + '.fcsfolder.zip'
	FileReader(LoadFile.filepath)


# def LoadFileToRAM(file):
# 	if platform == "linux":
# 		with open(file, 'rb') as f:
# 			FileReader.data = ( mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ) ).read()

# 	elif (platform == "win32") or (platform == "cygwin"):
# 		with open(file, 'rb') as f:
# 			FileReader.data = ( mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) ).read()


# def WriteFileFromRAM(file):
# 	try:
# 		with open(file, 'wb') as enc_file:
# 			if platform == "linux":
# 				mmap.mmap(enc_file.fileno(), 0, prot=mmap.PROT_WRITE)
# 			elif (platform == "win32") or (platform == "cygwin"):
# 				mmap.mmap(enc_file.fileno(), 0, access=mmap.ACCESS_WRITE)
# 	except Exception as e:
# 		print(e)

def LoadFile():

	if Load_Type.get() == 1: # Load_Type is folder
		LoadFile.Load_folder_addr = filedialog.askdirectory(title="Select A Folder")
		if LoadFile.Load_folder_addr:
			LoadFile.addr_filename, LoadFile.name_filename = os.path.split(LoadFile.Load_folder_addr) # address of directories | filename.*
			LoadFile.full_filename_path = LoadFile.addr_filename + "/" + LoadFile.name_filename # example/test/file.txt
			LoadFile.filepath = os.path.join(LoadFile.addr_filename, LoadFile.name_filename) # fix filepath format
			InputsButtonsSwitcher( [AES_encrypt_random_key_generator_button,key_input_encrypt], 'normal' )
			if len(LoadFile.full_filename_path) > 47:
				LoadFile.full_filename_path = LoadFile.full_filename_path[:25]+".../..."+LoadFile.full_filename_path[len(LoadFile.full_filename_path)-20:]

			Load_Button['text'] = LoadFile.full_filename_path # Update LoadFile Button text with loaded file path

	else: # Load_Type is file
		LoadFile.Load_filename_addr = filedialog.askopenfilenames(parent=gui, title='Choose File(s)', filetypes=[("All Files", "*.*")])
		if LoadFile.Load_filename_addr: # If user selected at least 1
			if len(LoadFile.Load_filename_addr) == 1:
				R1['text'] = "File"
				AES_encrypt_button['command'] = AES_Encrypt
				LoadFile.Load_filename_addr = LoadFile.Load_filename_addr[0]
				FileAddressFixer(LoadFile.Load_filename_addr)
				FileReader(LoadFile.filepath)
				InputsButtonsSwitcher( [AES_encrypt_random_key_generator_button,key_input_encrypt], 'normal' )
				
				if len(LoadFile.full_filename_path) > 47:
					LoadFile.full_filename_path = LoadFile.full_filename_path[:25]+".../..."+LoadFile.full_filename_path[len(LoadFile.full_filename_path)-20:]

				Load_Button['text'] = LoadFile.full_filename_path # Update LoadFile Button text with loaded file path

			else: # If user wants to choose more than one files
				R1['text'] = "Files"
				AES_encrypt_button['command'] = ManyFilesEncrypt
				Logger('info',f"You have chosen: {LoadFile.Load_filename_addr}" )
				Load_Button['text'] = "Selected {} files".format(len(LoadFile.Load_filename_addr))
				key_input_encrypt.delete(0,END)
				InputsButtonsSwitcher( [AES_encrypt_random_key_generator_button,key_input_encrypt], 'disable' ) # disable specific objects
				FileAddressFixer(LoadFile.Load_filename_addr)


def ManyFilesEncrypt():
	key_input_label_encrypt['text'] = 'Key (Hex):'
	for i in range(len(LoadFile.filepath)):
		Logger('info',f"Encrypting {LoadFile.name_filename[i]}")
		FileReader(LoadFile.filepath[i])
		key = bytes.fromhex(get_random_bytes(ChangeKeyGenBits.keybytes).hex())
		Data_Encrypt(LoadFile.filepath[i],key)


def InputsButtonsSwitcher(objects,state):
	for cur_obj in objects:
		cur_obj['state'] = state


def FileAddressFixer(Load_filename_addr):
	if isinstance(Load_filename_addr,str): # If Load_filename_addr is string (so only 1 file has been chosen)
		LoadFile.addr_filename, LoadFile.name_filename = os.path.split(Load_filename_addr) # address of directories | filename.*
		LoadFile.full_filename_path = LoadFile.addr_filename + "/" + LoadFile.name_filename # example/test/file.txt
		LoadFile.filepath = os.path.join(LoadFile.addr_filename, LoadFile.name_filename) # fix filepath format
		

	else: # If Load_filename_addr is list (so more than 1 files have been chosen)
		LoadFile.addr_filename = []
		LoadFile.name_filename = []
		LoadFile.full_filename_path = []
		LoadFile.filepath = []
		

		for i in range(len(Load_filename_addr)):
			LoadFile.addr_filename.append(os.path.split(Load_filename_addr[i])[0]) # address of directories
			LoadFile.name_filename.append(os.path.split(Load_filename_addr[i])[1]) # filename.*

			LoadFile.full_filename_path.append(LoadFile.addr_filename[i] + "/" + LoadFile.name_filename[i]) # example/test/file.txt
			LoadFile.filepath.append(os.path.join(LoadFile.addr_filename[i], LoadFile.name_filename[i])) # fix filepath format


def FileSha256Hasher(file):
	file_hash = hashlib.sha256(file).hexdigest()
	return file_hash


def QuickDecryptChecker(file_hash): # Check if encrypted file is in Keys Backup file
	if path.exists(Keys_Backup_file):

		with open(Keys_Backup_file,'r') as f:
			for line in f.readlines():
				if file_hash in line:
					Logger('info',"This file has been found in the Keys Backup file, so key and nonce have been filled automatically.")
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



row_num = 7
###--- Logger ---###
log_label = Label(gui, text="Log:", anchor=W).grid(row=row_num, column=0, pady=15, sticky='W')
Logging_window = scrolledtext.ScrolledText(gui, width = 100, height = 10)
Logging_window.configure(state='disabled')
Logging_window.grid(row=row_num, column=1, columnspan=4, pady=15)
###___ Logger ___###


DefaultSettingsSetter() # Set default Settings


#####---- Menu Bars ----####
settings_menubar = Menu(gui)


###--- Menu Settings ---###
view_main_menu = Menu(settings_menubar)

view_main_menu.add_command(label="Check for updates", command=UpdateCheck)
view_main_menu.add_checkbutton(label="Delete original file after encryption/decryption", onvalue=1, offvalue=0, variable=Delete_original_file_checkbox_value)
view_main_menu.add_checkbutton(label="Store key/nonce in backup file", onvalue=1, offvalue=0, variable=Backup_key_nonce_setting_value)
view_main_menu.add_checkbutton(label="Check if generated key is already in use", onvalue=1, offvalue=0, variable=Generated_key_in_use_checker_value)

Load_file_in_ram_value = 0
# view_main_menu.add_checkbutton(label="Load file in RAM", onvalue=1, offvalue=0, variable=Load_file_in_ram_value)
view_main_menu.add_command(label="Save Settings", command=SettingsSave)

settings_menubar.add_cascade(label='Menu Settings', menu=view_main_menu)
###___ Menu Settings ___###

###--- Keys Backup Settings ---###
view_Keys_Backup_file_menu = Menu(settings_menubar)

view_Keys_Backup_file_menu.add_command(label="Select Keys Backup file", command=ImportKeysBackupFile)

settings_menubar.add_cascade(label='Keys Backup File Settings', menu=view_Keys_Backup_file_menu)
###___ Keys Backup Settings ___###


gui.config(menu=settings_menubar)
#####____ Menu Bars ____####


row_num = 0
###--- Logo ---###
photo = PhotoImage(file = "logo.png")
gui.iconphoto(False, photo)
logo_img  = Image.open("Letters_logo.png") # logo
img=ImageTk.PhotoImage(logo_img)
lab=Label(image=img).grid(row=row_num, columnspan=2, sticky=W)
###___ Logo ___###


row_num = 2
###--- Load Button ---###
Load_Button = Button(gui, text="Load File/Folder", height=2, width=65, command=LoadFile)
Load_Button.grid(row=row_num,column=0,columnspan=2, pady=5, sticky=W)
###___ Load Button ___###


###--- Load Settings ---###
Load_Type = IntVar()
R1 = Radiobutton(gui, text="File", variable=Load_Type, value=0)
R1.grid(row=row_num,column=1, sticky=E, ipadx=20)
R2 = Radiobutton(gui, text="Folder", variable=Load_Type, value=1)
R2.grid(row=row_num,column=2, sticky=W)
###___ Load Settings ___###


row_num = 3
####--- AES Encrypt ---####


###--- Key Input ---###
key_input_label_encrypt = Label(gui, text="Key (Bts):")
key_input_label_encrypt.grid(row=row_num, column=0, sticky='W')
key_input_label_encrypt.bind('<Button-1>',EncryptKeyBytesHexFormat)
key_input_encrypt = Entry(gui, width=70, borderwidth=1)
key_input_encrypt.grid(row=row_num, column=1, padx=5, pady=40)
###___ Key Input ___###

###--- Generate Key Button ---###
AES_encrypt_random_key_generator_button = Button(gui, text ="Generate 256bits Key (Hex)", height=2, padx=5, fg="green2", bg="black", command=KeyRandomGenerator)
AES_encrypt_random_key_generator_button.grid(row=row_num, column=2, rowspan=2, sticky=W)
AES_encrypt_random_key_generator_button.bind("<Button-3>", ChangeKeyGenBits)
###___ Generate Key Button ___###

AES_encrypt_button = Button(gui, text ="AES Encrypt", height=2, padx=5, fg="green2", bg="black", command=AES_Encrypt) #AES Encrypt Button
AES_encrypt_button.grid(row=row_num, column=3, rowspan=2, sticky=W)

####___ AES Encrypt ___####





row_num = 5
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




gui.mainloop()
