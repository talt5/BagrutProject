##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Client
##############################################################
import tkinter as tk
from tkinter import font as tkfont
import threading
import socket
import hashlib
import os
# import panda3d
from enum import IntEnum
from cryptography.fernet import Fernet


class ServerComms:
    def __init__(self, server_ip, server_port):
        self.server_ip = server_ip
        self.server_port = server_port
        self.commsdata = ServerCommsData()
        self.client = None

    def start(self):
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((Constants.SERVER, Constants.PORT))
            self.client = client
            recv = threading.Thread(target=self.receive_packet)
            recv.start()
        except socket.error as e:
            print(e)

    def receive_packet(self):
        connected = True

        while connected:
            try:
                print(f"active connections {threading.active_count() - 1}")
                packet_header = int(self.client.recv(Constants.HEADER_LENGTH).decode())
                packet_data = self.client.recv(Constants.PACKET_SIZE - Constants.HEADER_LENGTH)
                print(packet_header)
                self.handle_packet(packet_header, packet_data)
            except Exception as error:
                connected = False
                print(error)
        self.client.close()

    # TODO: make an error message in tkinter if connection was cut during transmission.
    def send_to_server(self, header, msg):
        try:
            while True:
                header = str(header).zfill(Constants.HEADER_LENGTH)
                packet = header + str(msg)
                print(packet)
                self.client.send(packet.encode(Constants.FORMAT))
                break
        except socket.error as e:
            print(e)

    def register_action(self, fullname, email, phonenum, username, password):

        self.send_to_server(ResponseCodes.ASK_FOR_SALT_HEADER_CODE, "saltpls")

        while self.commsdata.get_salt() is None:
            continue

        # TODO: make an error message for each blacklisted entry
        if self.check_if_in_blacklist_reg(fullname, email, phonenum, username, password) != 0:
            print("data is in blacklist")
            return

        password = self.password_encrypt(password)
        header = ResponseCodes.REGIST_HEADER_CODE
        msg = str(fullname) + Constants.SEPERATOR + str(email) + Constants.SEPERATOR + str(
            phonenum) + Constants.SEPERATOR + str(
            username) + Constants.SEPERATOR + str(password)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()
        self.commsdata.set_salt(None)

    def login_action(self, username, password):
        self.commsdata.set_salt(None)
        self.send_to_server(ResponseCodes.ASK_FOR_SALT_HEADER_CODE, "saltpls")

        while self.commsdata.get_salt() is None:
            pass

        # TODO: make an error message for each blacklisted entry
        if self.check_if_in_blacklist_login(username, password) != 0:
            print("data is in blacklist")
            return

        password = self.password_encrypt(password)
        header = ResponseCodes.LOGIN_HEADER_CODE
        msg = str(username) + Constants.SEPERATOR + str(password)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()
        self.commsdata.set_salt(None)

    def handle_packet(self, header, data):
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
                seperated_data = data.decode().split(Constants.SEPERATOR)
                self.commsdata.set_userId(seperated_data[0])
                self.commsdata.set_username(seperated_data[1])
                self.commsdata.set_nickname(seperated_data[2])
                app.show_frame("ChatPage")
            case ResponseCodes.LOGIN_FAIL_HEADER_CODE:
                print("Failed to login - wrong user or pass")
            case ResponseCodes.LOGIN_FAIL_INBLACK_HEADER_CODE:
                print("Failed to login - input in blacklist")
            case ResponseCodes.ASK_FOR_SALT_HEADER_CODE:
                self.commsdata.set_salt(data.decode())
            case ResponseCodes.ASK_FOR_SALT_FAIL_HEADER_CODE:
                print("Failed to get salt")

    def password_encrypt(self, password):
        local_salt = "saltysaltsohot".encode()
        f = Fernet(self.commsdata.get_salt())
        hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), local_salt, 100000).hex().encode()
        encrypted_password = f.encrypt(hashed_password).decode()
        return encrypted_password

    def check_if_in_blacklist_reg(self, fullname, email, phonenum, username, password):
        blacklist = (Constants.SEPERATOR)
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

    def check_if_in_blacklist_login(self, username, password):
        blacklist = (Constants.SEPERATOR)
        if blacklist in username or not 1 <= len(username) <= 32:
            return 4
        if blacklist in password or not 1 <= len(password) <= 32:
            return 5
        return 0

    def commsdata(self):
        return self.commsdata


def represents_int(data):
    try:
        int(data)
    except ValueError:
        return False
    else:
        return True


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
    NOTLOGGEDIN_HEADER_CODE = 4


class App(tk.Tk):
    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.title_font = tkfont.Font(family="Helvetica", size=18, weight="bold")
        self.servercomms = ServerComms("127.0.0.1", Constants.PORT)
        self.servercomms.start()

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for Frame in (StartPage, LoginPage, RegistrationPage, ChatPage):
            page_name = Frame.__name__
            frame = Frame(parent=container, controller=self)
            self.frames[page_name] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame("StartPage")

    def servercomms(self):
        return self.servercomms

    def show_frame(self, page_name):
        """Show a frame for the given page name"""
        frame = self.frames[page_name]
        frame.update_frame()
        frame.tkraise()


class StartPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="This is the start page", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Go to Page One",
                            command=lambda: controller.show_frame("LoginPage"))
        button2 = tk.Button(self, text="Go to Page Two",
                            command=lambda: controller.show_frame("RegistrationPage"))
        button1.pack()
        button2.pack()

    def update_frame(self):
        pass


class LoginPage(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        username_login_entry = tk.Entry(self, width=60)
        username_login_entry.insert(0, "Username")
        password_login_entry = tk.Entry(self, width=60)
        password_login_entry.insert(0, "Password")
        submit_reg_button = tk.Button(self, text="Submit",
                                      command=lambda: threading.Thread(controller.servercomms.login_action(
                                          username_login_entry.get(),
                                          password_login_entry.get())).start())
        back_button = tk.Button(self, text="Back", command=lambda: controller.show_frame("StartPage"))
        username_login_entry.pack()
        password_login_entry.pack()
        submit_reg_button.pack()
        back_button.pack()

    def update_frame(self):
        pass


class RegistrationPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        full_name_reg_entry = tk.Entry(self, width=60)
        full_name_reg_entry.insert(0, "Full name")
        email_reg_entry = tk.Entry(self, width=60)
        email_reg_entry.insert(0, "Email")
        username_reg_entry = tk.Entry(self, width=60)
        username_reg_entry.insert(0, "Username")
        password_reg_entry = tk.Entry(self, width=60)
        password_reg_entry.insert(0, "Password")
        phonenum_reg_entry = tk.Entry(self, width=60)
        phonenum_reg_entry.insert(0, "Phone number")
        submit_reg_button = tk.Button(self, text="Submit",
                                      command=lambda: threading.Thread(controller.servercomms.register_action(
                                          full_name_reg_entry.get(),
                                          email_reg_entry.get(),
                                          phonenum_reg_entry.get(),
                                          username_reg_entry.get(),
                                          password_reg_entry.get())).start())
        back_button = tk.Button(self, text="Back", command=lambda: controller.show_frame("StartPage"))
        full_name_reg_entry.pack()
        email_reg_entry.pack()
        phonenum_reg_entry.pack()
        username_reg_entry.pack()
        password_reg_entry.pack()
        submit_reg_button.pack()
        back_button.pack()

    def update_frame(self):
        pass


class ChatPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

    def update_frame(self):
        username_label = tk.Label(self, text=("Logged in as: " + self.controller.servercomms.commsdata.get_nickname()),
                                  font=self.controller.title_font)
        username_label.pack()


class ServerCommsData:
    def __init__(self):
        self.salt = None
        self.userId = None
        self.username = None
        self.nickname = None

    def get_salt(self):
        return self.salt

    def set_salt(self, salt):
        self.salt = salt

    def get_userId(self):
        return self.userId

    def set_userId(self, ID):
        self.userId = ID

    def get_username(self):
        return self.username

    def set_username(self, username):
        self.username = username

    def get_nickname(self):
        return self.nickname

    def set_nickname(self, nickname):
        self.nickname = nickname


class Constants:
    PACKET_SIZE = 1024
    HEADER_LENGTH = 64
    SERVER = "127.0.0.1"
    PORT = 8820
    FORMAT = "utf-8"
    SEPERATOR = "█"


if __name__ == "__main__":
    app = App()
    app.mainloop()
