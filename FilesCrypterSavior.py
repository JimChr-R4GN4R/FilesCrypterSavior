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


###--- Methods ---###


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
		if len(Key_input_decrypt.get()) > 32:
			Key_input_decrypt.delete(32,END)
			messagebox.showerror("Key's Length Error", "This key hex value should not be more than 32 bytes.\nLength has been fixed")
			key_input_label_decrypt['text'] = "Key (Bts):"
		else:
			key_input_label_decrypt['text'] = "Key (Bts):"
	else:
		if len(Key_input_decrypt.get()) > 32:
			messagebox.showerror("Key's Length Error", "Your key should not be more than 32 bytes.\nLength has been fixed")
			Key_input_decrypt.delete(32,END)
			key_input_label_decrypt['text'] = "Key (Hex):"
		else:
			key_input_label_decrypt['text'] = "Key (Hex):"


def Data_Encrypt(key): # Encrypt Data
		try:
			cipher = AES.new(key, AES.MODE_EAX)
			nonce = cipher.nonce ; Logger( 'imp',"Nonce (hex): " + nonce.hex() ) # sign nonce
			Logger('info',"Encrypting with AES-GCM...")
			LoadFile.data = pad(LoadFile.data,16) # Fix file bytes length
			enc_bytes = cipher.encrypt(LoadFile.data) # Encrypting...

			enc_file = open(LoadFile.filepath+'.fcsenc', 'wb') # Make new enc_file
			enc_file.write(enc_bytes) # Write encrypted bytes in enc_file 
			enc_file.close()

			if Delete_original_file_checkbox_value.get():
				os.remove(LoadFile.filepath) # delete original file

			if Backup_keyFile_value.get(): # Option Backup key and nonce to file_keys_backup.txt enabled
				with open('file_keys_backup.txt', 'a') as enc_file:

					if '(Bts)' in key_input_label_encrypt['text']:
						enc_file.write(LoadFile.filepath + '.fcsenc' + " | Key: "+unpad(key,16).decode('utf-8') + " | " + "Nonce (hex): "+nonce.hex())
					else:
						enc_file.write(LoadFile.filepath + '.fcsenc' + " | Key (hex): " + key.hex() + " | " + "Nonce (hex): "+nonce.hex() + '\n')

			Logger('info',"Encryption Finished.")
			
		except ValueError:
			Logger('error',"[DE-1] Encryption Failed. Please check your key's length and value")
		


def AES_Encrypt(): # AES Encrypt

	if Load_file_Button['text'] == "Load File":
		Logger('warn',"Please select a file to encrypt.")

	elif path.exists(LoadFile.filepath): # file exists

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

	if Load_file_Button['text'] == "Load File":
		Logger('warn',"Please select a file to encrypt.")

	elif path.exists(LoadFile.filepath): # file exists
		key = Key_input_decrypt.get()
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
				Logger('info',"Decrypting with AES-GCM...")

				try:
					dec_bytes = unpad(cipher.decrypt(LoadFile.data),16)
					dec_file = open(LoadFile.filepath[:-7], 'wb')
					dec_file.write(dec_bytes)
					dec_file.close()
					os.remove(LoadFile.filepath) # Delete encrypted file and backup_keys
					Logger('info',"Decryption Finished.")

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


def LoadFile():

	Load_filename_addr = filedialog.askopenfilename(title="Select A File", filetypes=[("All Files", "*.*")] ) # import file

	if Load_filename_addr:
		LoadFile.addr_filename, LoadFile.name_filename = os.path.split(Load_filename_addr) # address of directories | filename.*

		LoadFile.full_filename_path = LoadFile.addr_filename + "/" + LoadFile.name_filename # example/test/file.txt


		LoadFile.filepath = os.path.join(LoadFile.addr_filename, LoadFile.name_filename)


		LoadFile.data = open(LoadFile.full_filename_path, 'rb').read() # import data from file.txt

		if len(LoadFile.full_filename_path) > 47:
			LoadFile.full_filename_path = LoadFile.full_filename_path[:25]+".../..."+LoadFile.full_filename_path[len(LoadFile.full_filename_path)-20:]

		Load_file_Button['text'] = LoadFile.full_filename_path # Update LoadFile Button text with loaded file path


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


###___ Methods ___###




gui = Tk(className='FilesCrypterSavior V1.0')
gui.geometry("900x460")
gui.resizable(False,False)




###--- Default Values ---###
ChangeKeyGenBits.keybytes = 128//8 # Default generate key bytes length
LoadFile.filepath = "-" # Default filepath which does not exist
###___ Default Values ___###


####--- Menu Options ---####

menubar = Menu(gui)
view_menu = Menu(menubar)

###--- Option 1 ---###
Delete_original_file_checkbox_value = IntVar(value=1)
view_menu.add_checkbutton(label="Delete original file after encryption/decryption", onvalue=1, offvalue=0, variable=Delete_original_file_checkbox_value)
###___ Option 1 ___###

###--- Option 2 ---###
Backup_keyFile_value = IntVar(value=1)
view_menu.add_checkbutton(label="Add key and nonce in the database", onvalue=1, offvalue=0, variable=Backup_keyFile_value)
###___ Option 2 ___###

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
###--- Load File Button ---###
Load_file_Button = Button(gui, text="Load File", height=2, width=60, command=LoadFile)
Load_file_Button.grid(row=row_num,column=0,columnspan=3, pady=5, sticky=W)
###___ Load File Button ___###


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
Key_input_decrypt = Entry(gui, width=70, borderwidth=1)
Key_input_decrypt.grid(row=row_num, column=1, padx=15)
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
