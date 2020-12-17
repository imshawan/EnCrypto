import base64
import os
import iconpack
from time import sleep
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import tkinter as tk
import tkinter.font as font
from tkinter.ttk import *
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog, Text

root = tk.Tk()
root.title('EnCrypto by Shawan Mandal')
root.resizable(0,0)
def dt():
    global t1
    t = datetime.now()
    t1 = t.strftime('%H:%M:%S')

def resetall():
    for things in frame.winfo_children():
        things.destroy()
    for things in savefrm.winfo_children():
        things.destroy()
    for things in outputc.winfo_children():
        things.destroy()
    inputtxt.delete("1.0", "end")
    outfilenm.delete("1.0", "end")

def select_file():
    global filename
    for things in frame.winfo_children():
        things.destroy()
    filename = filedialog.askopenfilename(initialdir="/", title="Select File",
                                          filetypes=(("executables", "*.exe"),("archives", "*.zip;*.rar"),("documents", "*.doc;*.docx;*.pdf"),("pictures", "*.jpg;*.jpeg;*.png;*.bmp"),
                                                     ("text", "*.txt;*.otf"),("webpage","*.htm;*.html;*.cshtml;*.mht;*.php;*.xml"),("scripts","*.bat;*.vbs;*.cmd;*.css;*.js"),("all files","*.*")))
    
    label = tk.Label(frame, text=filename, bg='white')
    label.pack()

def wheretosavefile():
    global foldername
    for things in savefrm.winfo_children():
        things.destroy()
    foldername = filedialog.askdirectory()
    
    label1 = tk.Label(savefrm, text=foldername, bg='white')
    label1.pack()


def obox(o1):
    dt()
    for things in outputc.winfo_children():
        things.destroy()
    outputc1 = tk.Label(outputc, text=f'[{t1}]: {o1}', bg='white')
    outputc1.place(x=25, y=13)
def obox1(o2):
    dt()
    outputc2 = tk.Label(outputc, text=f'[{t1}]: {o2}', bg='white')
    outputc2.place(x=25, y=33)
def obox2(o3):
    dt()
    outputc3 = tk.Label(outputc, text=f'[{t1}]: {o3}', bg='white')
    outputc3.place(x=25, y=53)
def obox3(o4):
    dt()
    outputc4 = tk.Label(outputc, text=f'[{t1}]: {o4}', bg='white')
    outputc4.place(x=25, y=73)
def outputconsole(output):
    dt()
    outputconsole = tk.Label(outputc, text=f'[{t1}]: {output}', bg='white')
    outputconsole.place(x=25, y=93)

def Encrypt():
    INPUT = inputtxt.get("1.0", 'end-1c')
    password_provided = INPUT # This is input in the form of a string
    try:
        input_file = filename
    except NameError:
        messagebox.showwarning('Warning!', 'You need to select file first!')
        return

    if INPUT=="":
        messagebox.showwarning('Warning!', 'Password Field is Empty')
        return
    outputfile = outfilenm.get("1.0", 'end-1c')
    newdir = "Encrypted-DATA"
    try:
        path = os.path.join(foldername, newdir)
    except NameError:
        messagebox.showerror('Error!', 'Output Path not set')
        return
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        pass
    if outputfile=="":
        messagebox.showwarning('Warning!', 'Enter Output Filename')
        return
    output_file = os.path.abspath(path + "\encrypted-" + outputfile)
    obox("Reading Bytes")
    with open(input_file, 'rb') as f:
        data = f.read()  # Read the bytes of the input file
    password = password_provided.encode()  # Convert to type bytes
    salt = b'|\xd8\x99M\xc0C\xee->o\xf8\x90w\xd1\xc50'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    obox1("Applying Salt")
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet = Fernet(key)
    obox2("Encrypting Bytes")
    encrypted = fernet.encrypt(data)
    obox3("Writing Encrypted bytes to file")
    sleep
    with open(output_file, 'wb') as f:
        f.write(encrypted)      # Write the encrypted bytes to the output file
        outputconsole("Encrypted")
        messagebox.showinfo('Success!', 'Encryption Completed Successfully')
    keyFile = os.path.abspath(path + "\info.txt")
    with open(keyFile, 'w') as writefile:
        writefile.write(f'Encryption Key: {password_provided}\nFile Address: {input_file}\n')
    

def Decrypt():
    INPUT = inputtxt.get("1.0", 'end-1c')
    password_provided = INPUT # This is input in the form of a string
    try:
        input_file = filename
    except NameError:
        messagebox.showwarning('Warning!', "You need to select file first!")
        return
    if INPUT=="":
        messagebox.showwarning('Warning!', 'Enter Decryption Key!')
        return
    outputfile = outfilenm.get("1.0", 'end-1c')
    newdir = "Decrypted-DATA"
    try:
        path = os.path.join(foldername, newdir)
    except NameError:
        messagebox.showerror('Error!', 'Output Path not set')
        return
    
    if not os.path.exists(path):
        os.makedirs(path)
    else:
        pass
    if outputfile=="":
        messagebox.showwarning('Warning!', 'Enter Output Filename')
        return
    output_file = os.path.abspath(path + "\decrypted-" + outputfile)
    obox("Reading Bytes")
    with open(input_file, 'rb') as f:
        data = f.read()  # Read the bytes of the encrypted file
    password = password_provided.encode()  # Convert to type bytes
    obox1("Analysing Passkey")
    salt = b'|\xd8\x99M\xc0C\xee->o\xf8\x90w\xd1\xc50'
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    fernet = Fernet(key)
    try:
        obox2("Trying to decrypt Bytes")
        decrypted = fernet.decrypt(data)
        obox3("Writing Encrypted bytes to file")
        with open(output_file, 'wb') as f:
            f.write(decrypted)  # Write the decrypted bytes to the output file
            outputconsole("Successfully Decrypted")
            messagebox.showinfo('Success!', 'Decryption Completed Successfully')
    except InvalidToken as e:
        messagebox.showerror('Error!', "Incorrect Decryption Key!")
        return


canvas = tk.Canvas(root, height=500, width=500, bg='#d9d9d9')
canvas.pack()

MAIN_ICON = iconpack.APP_ICON
if not os.path.isfile('enc.png'):
    base64_img_bytes = MAIN_ICON.encode('utf-8')
    with open('enc.png', 'wb') as file_to_save:
        decoded_image_data = base64.decodebytes(base64_img_bytes)
        file_to_save.write(decoded_image_data)
else:
    ico = PhotoImage(file='enc.png')
    root.iconphoto(False, ico)

header = tk.Label(root, text="ENCRYPTO", bg='#d9d9d9', fg='black', relief="flat")
header.configure(font='"Riky Vampdator Normal" 33')
#header.configure(font='"Elianto" 33')
header.place(x=132, y=10)
subhead = tk.Label(root, text="A Simple Encrypter/Decrypter", bg='#d9d9d9')
subhead.place(x=168, y=65)

inptxt = tk.Label(root, text="Enter Your Encryption/Decryption Key: ")
inptxt.place(x=25, y=140)
inputtxt = Text(root, height=1, width=56, bg = 'white')
inputtxt.place(x=25, y=165)
getencry = tk.Button(root, text="Encrypt File", width=10, bd=1, command=Encrypt)
getencry.place(x=103, y=290)

getdecry = tk.Button(root, text="Decrypt File", width=10, bd=1, command=Decrypt)
getdecry.place(x=208, y=290)

reset = tk.Button(root, text="Reset All", width=10, bd=1, command=resetall)
reset.place(x=313, y=290)

txt = tk.Label(root, text="Select Directory for saving the Output file:")
txt.place(x=25, y=195)
savefl = tk.Button(root, text="Save as", bd=1, command=wheretosavefile)
savefl.place(x=25, y=220)
savefrm = tk.Frame(root, bg='white')
savefrm.place(width=395, height=20 ,x=81, y=222)
txt1 = tk.Label(root, text="Enter Output Filename (with file extension):")
txt1.place(x=25, y=253)
outfilenm = Text(root, height=1, width=26, bg = 'white')
outfilenm.place(x=264, y=253)

outputc = tk.Frame(root, bg='white')
outputc.place(x=50, y=335, height=130, width=400)

frame = tk.Frame(root, bg='white')
frame.place(width=450, height=20, x=25, y=115)

openFile = tk.Button(root, text="Select File", width=10, fg='black', bd=1, command=select_file)
openFile.place(x=25, y=85)

copyrt = tk.Label(root, text="© 2020 Shawan Mandal.", fg='grey', bg='#d9d9d9')
copyrt.place(x=185, y=475)

root.mainloop()
