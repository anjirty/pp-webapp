import os
import time
import pyzipper
import py7zr
import itertools
import string
import pikepdf
from termcolor import colored
import threading
from pathlib import Path
from pywebio.input import *
from pywebio.output import *
from pywebio.session import *

def generate_passwords(min_length, max_length, char_set):
    """Generates a list of passwords within the specified parameters."""
    passwords = []
    for length in range(min_length, max_length + 1):
        passwords.extend(''.join(x) for x in itertools.product(char_set, repeat=length))
    return passwords

def write_to_file(file_path, password, file_name, file_type):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
    except FileNotFoundError:
        lines = []

    if f"To access {file_name}, use the password {password}\n" in lines:
        time.sleep(2)
        print(colored(f'To access {file_name}, use the password {password}\n', 'blue'))
        put_text(f"To access {file_name}, use the password {password}")
    else:
        with open(f"{file_type.upper()}.txt", 'a') as file:
            time.sleep(2)
            file.write(f"To access {file_name}, use the password {password}\n")
            print(colored(f'To access {file_name}, use the password {password}\n', 'green'))
            put_text(f"To access {file_name}, use the password {password}")
def decrypt_zip(zip_file, passwords):
    """Attempts to decrypt the ZIP file with a list of passwords."""
    with pyzipper.AESZipFile(zip_file) as f:
        for password in passwords:
            try:
                path = zip_file
                pathx = Path(path).stem + '.zip'
                f.extractall(pwd=password.encode())
                write_to_file("ZIP.txt", password, pathx, "zip")
                return password
            except RuntimeError:
                print(colored(f"[-] Incorrect Password: {password}", 'red', attrs=['bold']))
                os.system('cls' if os.name == 'nt' else 'clear')
    print(colored('[!] No valid passwords were found', 'red', attrs=['bold']))
    put_text('[!] No valid passwords were found')
def decrypt_7z(archive_file, passwords):
    """Attempts to decrypt the 7Z archive with a list of passwords."""
    for password in passwords:
        try:
            path = archive_file
            pathx = Path(path).stem + '.7z'
            with py7zr.SevenZipFile(archive_file, mode='r', password=password) as f:
                f.extractall()
                write_to_file("7Z.txt", password, pathx, "7z")
                return password
        except py7zr.Bad7zFile:
            print(colored(f"[-] Incorrect Password: {password}. File: {archive_file}", 'red', attrs=['bold']))
            os.system('cls' if os.name == 'nt' else 'clear')
        except RuntimeError:
            print(colored(f"[-] Error occurred while decrypting: {archive_file}", 'red', attrs=['bold']))
            os.system('cls' if os.name == 'nt' else 'clear')
    print(colored('[!] No valid passwords were found', 'red', attrs=['bold']))
    put_text('[!] No valid passwords were found')
def decrypt_pdf(pdf_file, passwords):
    """Attempts to brute force the PDF file with a list of passwords using pikepdf."""
    for password in passwords:
        try:
            with pikepdf.open(pdf_file, password=password) as pdf:
                path = pdf_file
                pathx = Path(path).stem + '.pdf'
                write_to_file("PDF.txt", password, pathx, "pdf")
                return password
        except pikepdf.PasswordError:
            print(colored(f"[-] Incorrect Password: {password}", 'red', attrs=['bold']))
            os.system('cls' if os.name == 'nt' else 'clear')
    print(colored('[!] No valid passwords were found !!', 'red', attrs=['bold']))
    put_text('[!] No valid passwords were found')
def check_option(option):
    if option == 'Wordlist':
        choice = 'w'
        password_list_info = file_upload("Upload your wordlist", accept='.txt')
        password_list_content = password_list_info['content'].decode()  # Extract the content of the wordlist file
        passwords = [line.strip() for line in password_list_content.split('\n')]  # Split the content into lines and remove leading/trailing whitespace
        print(f"[=] Using passwords from the uploaded wordlist.")
    elif option == 'PassGen':
        choice = 'g'
        min_length = input("Minimum Length", type=NUMBER)
        max_length = input("Maximum Length", type=NUMBER)
        char_set = input("Specific Characters", type=TEXT)
        if not char_set:
            char_set = string.ascii_letters + string.digits
        passwords = generate_passwords(min_length, max_length, char_set)
        print(f"[=] Generated {len(passwords)} passwords:")
    else:
        print(colored(f"[!] Invalid choice. Please choose 'p' for password list or 'g' for password generation.", 'red', attrs=['bold']))
        exit(1)

    return passwords


import tempfile

def app():
    file_info = file_upload("Upload your file", accept='.pdf,.zip,.7z')
    file_content = file_info['content']  # Extract the file content from the dictionary
    file_type = input("File Type [zip, pdf, 7z]", type=TEXT)
    option = checkbox("Choose an option", options=['Wordlist', 'PassGen'])

    if len(option) > 1:
        toast("Only one option can be selected", color='error')
        return
    else:
        passwords = check_option(option[0])  # Store the returned passwords list

    # Write the uploaded file's content to a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as temp_file:
        temp_file.write(file_content)
        file_path = temp_file.name  # Get the path of the temporary file

    put_buttons(['Submit'], onclick=[lambda: decrypt_files(file_type, file_path, passwords)])

    threads = []
    for file_path in [file_path]:
        t = threading.Thread(target=decrypt_files, args=(file_type, file_path, passwords))
        threads.append(t)
        t.start()


def decrypt_files(file_type, file_path, passwords):  # Add filetypo as a parameter
    if file_type.lower() == 'zip':
        return decrypt_zip(file_path, passwords)
    elif file_type.lower() == '7z':
        return decrypt_7z(file_path, passwords)
    elif file_type.lower() == 'pdf':
        return decrypt_pdf(file_path, passwords)
    else:
       print(colored(f"[!] Error: Invalid file format. Please try with a ZIP, 7Z, or PDF file.", "red", attrs=["bold"]))
       return None

if __name__ == '__main__':
    from pywebio.platform.tornado_http import start_server
    start_server(app, port=8080)
