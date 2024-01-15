##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Client
##############################################################
import tkinter as tk
import threading
import socket
import hashlib
import os
import panda3d
from enum import IntEnum
from cryptography.fernet import Fernet

PACKET_SIZE = 1024
HEADER_LENGTH = 64


PORT = 8820
SERVER = "10.100.102.8"
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"
SEPERATOR = "█"

server_salt = None

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print(f"active connections {threading.active_count() - 1}")


def start_listening_to_server():
    client.connect(ADDRESS)
    recv = threading.Thread(target=receive_packet)
    recv.start()


def register_action(fullname, email, phonenum, username, password):
    global server_salt
    server_salt = None
    send_to_server(ResponseCodes.ASK_FOR_SALT_HEADER_CODE, "saltpls")
    while server_salt is None:
        continue
    if check_if_in_blacklist_reg(fullname, email, phonenum, username, password) != 0:
        print("data is in blacklist")
        return
    password = password_encrypt(password)
    header = ResponseCodes.REGIST_HEADER_CODE
    msg = str(fullname) + SEPERATOR + str(email) + SEPERATOR + str(phonenum) + SEPERATOR + str(
        username) + SEPERATOR + str(password)
    snd = threading.Thread(target=send_to_server(header, msg))
    snd.start()
    server_salt = None


def login_action(username, password):
    global server_salt
    server_salt = None
    send_to_server(ResponseCodes.ASK_FOR_SALT_HEADER_CODE, "saltpls")
    while server_salt is None:
        pass
    if check_if_in_blacklist_login(username, password) != 0:
        print("data is in blacklist")
        return
    password = password_encrypt(password)
    header = ResponseCodes.LOGIN_HEADER_CODE
    msg = str(username) + SEPERATOR + str(password)
    snd = threading.Thread(target=send_to_server(header, msg))
    snd.start()
    server_salt = None


def check_if_in_blacklist_reg(fullname, email, phonenum, username, password):
    blacklist = (SEPERATOR)
    if blacklist in fullname or not 0 < len(fullname) <= 64:
        return 1
    if blacklist in email or not 0 < len(email) <= 64:
        return 2
    if blacklist in phonenum or not represents_int(phonenum) or int(phonenum) <= 0 or not len(phonenum) == 10:
        return 3
    if blacklist in username or not 4 <= len(username) <= 32:
        return 4
    if blacklist in password or not 8 <= len(password) <= 32:
        return 5
    return 0


def check_if_in_blacklist_login(username, password):
    blacklist = (SEPERATOR)
    if blacklist in username or not 1 <= len(username) <= 32:
        return 4
    if blacklist in password or not 1 <= len(password) <= 32:
        return 5
    return 0


def represents_int(data):
    try:
        int(data)
    except ValueError:
        return False
    else:
        return True


def send_to_server(header, msg):
    while True:
        header = str(header).zfill(HEADER_LENGTH)
        packet = header + str(msg)
        print(packet)
        client.send(packet.encode(FORMAT))
        break


def receive_packet():
    connected = True
    while connected:
        try:
            print(f"active connections {threading.active_count() - 1}")
            packet_header = int(client.recv(HEADER_LENGTH).decode())
            packet_data = client.recv(PACKET_SIZE - HEADER_LENGTH)
            print(packet_header)
            handle_packet(packet_header, packet_data)
        except Exception as error:
            connected = False
            print(error)
    client.close()


class ResponseCodes(IntEnum):
    PACKET_SIZE = 1024
    HEADER_LENGTH = 64
    REGIST_HEADER_CODE = 1
    REGIST_SUCCESS_HEADER_CODE = 11
    REGIST_FAIL_HEADER_CODE = 12
    REGIST_FAIL_USREXIST_HEADER_CODE = 121
    REGIST_FAIL_INBLACK_HEADER_CODE = 122
    LOGIN_HEADER_CODE = 2
    LOGIN_SUCCESS_HEADER_CODE = 21
    LOGIN_FAIL_HEADER_CODE = 22
    LOGIN_FAIL_INBLACK_HEADER_CODE = 221
    ASK_FOR_SALT_HEADER_CODE = 3
    ASK_FOR_SALT_FAIL_HEADER_CODE = 32


def handle_packet(header, data):
    global server_salt
    match header:
        case ResponseCodes.REGIST_SUCCESS_HEADER_CODE:
            print("Successfully registered.")
        case ResponseCodes.REGIST_FAIL_HEADER_CODE:
            print("Failed to register")
        case ResponseCodes.REGIST_FAIL_HEADER_CODE:
            print("Failed to register")
        case ResponseCodes.REGIST_FAIL_USREXIST_HEADER_CODE:
            print("Failed to register - user already exists")
        case ResponseCodes.REGIST_FAIL_INBLACK_HEADER_CODE:
            print("Failed to register - input in blacklist")
        case ResponseCodes.LOGIN_SUCCESS_HEADER_CODE:
            print("Successfully logged in")
        case ResponseCodes.LOGIN_FAIL_HEADER_CODE:
            print("Failed to login - wrong user or pass")
        case ResponseCodes.LOGIN_FAIL_INBLACK_HEADER_CODE:
            print("Failed to login - input in blacklist")
        case ResponseCodes.ASK_FOR_SALT_HEADER_CODE:
            server_salt = data.decode()
        case ResponseCodes.ASK_FOR_SALT_FAIL_HEADER_CODE:
            print("Failed to get salt")


def password_encrypt(password):
    local_salt = "saltysaltsohot".encode()
    f = Fernet(server_salt)
    hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), local_salt, 100000).hex().encode()
    encrypted_password = f.encrypt(hashed_password).decode()
    return encrypted_password


def show_login_frame():
    loginframe = tk.Toplevel(root)
    username_login_entry = tk.Entry(loginframe, width=60)
    username_login_entry.insert(0, "Username")
    password_login_entry = tk.Entry(loginframe, width=60)
    password_login_entry.insert(0, "Password")
    submit_reg_button = tk.Button(loginframe, text="Submit", command=lambda: threading.Thread(login_action(
        username_login_entry.get(),
        password_login_entry.get())).start())
    username_login_entry.pack()
    password_login_entry.pack()
    submit_reg_button.pack()


def show_registration_frame():
    registrationframe = tk.Toplevel(root)
    full_name_reg_entry = tk.Entry(registrationframe, width=60)
    full_name_reg_entry.insert(0, "Full name")
    email_reg_entry = tk.Entry(registrationframe, width=60)
    email_reg_entry.insert(0, "Email")
    username_reg_entry = tk.Entry(registrationframe, width=60)
    username_reg_entry.insert(0, "Username")
    password_reg_entry = tk.Entry(registrationframe, width=60)
    password_reg_entry.insert(0, "Password")
    phonenum_reg_entry = tk.Entry(registrationframe, width=60)
    phonenum_reg_entry.insert(0, "Phone number")
    submit_reg_button = tk.Button(registrationframe, text="Submit", command=lambda: threading.Thread(register_action(
        full_name_reg_entry.get(),
        email_reg_entry.get(),
        phonenum_reg_entry.get(),
        username_reg_entry.get(),
        password_reg_entry.get())).start())
    full_name_reg_entry.pack()
    email_reg_entry.pack()
    phonenum_reg_entry.pack()
    username_reg_entry.pack()
    password_reg_entry.pack()
    submit_reg_button.pack()


# TK Init and frame creation
root = tk.Tk()
startingframe = tk.Frame(root)

root.title("Start menu")

# Creating TK UI Elements
# startingframe
login_button_start = tk.Button(startingframe, text="Login", command=show_login_frame)
registration_button_start = tk.Button(startingframe, text="Register", command=show_registration_frame)
# loginframe
# registrationframe
# TK UI Packing
# startingframe
login_button_start.pack()
registration_button_start.pack()
startingframe.pack()
# loginframe
# registrationframe
root.after(100, start_listening_to_server)

tk.mainloop()
