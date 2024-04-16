##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Client
##############################################################
import tkinter as tk
from tkinter import font as tkfont
import threading
import traceback
import socket
import hashlib
import os
# import panda3d
from enum import IntEnum
from rsa import RSAEncryption
from aes import AESEncryption


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
            self.ask_for_rsa_public_key()
        except socket.error as e:
            print(e)

    def receive_packet(self):
        connected = True

        while connected:
            try:
                if self.commsdata.encrypted_comms is True:
                    nonce_len = int(self.client.recv(2).decode())
                    nonce = self.client.recv(nonce_len)
                    packet_len = int(self.client.recv(4).decode())
                    packet = self.client.recv(packet_len)
                    decrypted_packet = self.commsdata.aes.decrypt_data(packet, nonce)
                    decrypted_header = int(decrypted_packet[:Constants.HEADER_LENGTH].decode())
                    decrypted_data = decrypted_packet[
                                     Constants.HEADER_LENGTH:(Constants.PACKET_SIZE - Constants.HEADER_LENGTH)]
                    print("received", nonce_len)
                    print("received", nonce)
                    print("received", decrypted_packet)
                    try:
                        print(decrypted_packet.decode())
                    except Exception as error:
                        print(traceback.format_exc())
                        connected = False
                        print(error)
                    self.handle_packet(decrypted_header, decrypted_data)
                else:
                    packet_header = int(self.client.recv(Constants.HEADER_LENGTH).decode())
                    packet_data = self.client.recv(Constants.PACKET_SIZE - Constants.HEADER_LENGTH)
                    print(packet_header)
                    print(packet_data)
                    self.handle_packet(packet_header, packet_data)
            except Exception as error:
                print(traceback.format_exc())
                connected = False
                print(error)
        self.client.close()

    # TODO: make an error message in tkinter if connection was cut during transmission.
    def send_to_server(self, header, msg):
        try:
            if self.commsdata.encrypted_comms is True:
                while True:
                    header = str(header).zfill(Constants.HEADER_LENGTH).encode()
                    if type(msg) is not bytes:
                        msg = msg.encode()
                    print("sending: ".encode() + header + msg)
                    encrypted_packet, nonce = self.commsdata.aes.encrypt_data(header + msg)
                    packet = str(len(nonce)).zfill(2).encode() + nonce + encrypted_packet
                    self.client.send(packet)
                    break
            else:
                while True:
                    header = str(header).zfill(Constants.HEADER_LENGTH)
                    if type(msg) is not bytes:
                        msg = msg.encode()

                    packet = header.encode() + msg
                    print("sending: ".encode() + packet)
                    self.client.send(packet)
                    break
        except socket.error as e:
            print(e)

    def register_action(self, fullname, email, phonenum, username, password):

        # TODO: make an error message for each blacklisted entry
        if self.check_if_in_blacklist_reg(fullname, email, phonenum, username, password) != 0:
            print("data is in blacklist")
            return

        password = self.password_hash(password)
        header = ResponseCodes.REGIST_HEADER_CODE
        msg = str(fullname) + Constants.SEPERATOR + str(email) + Constants.SEPERATOR + str(
            phonenum) + Constants.SEPERATOR + str(
            username) + Constants.SEPERATOR + str(password)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def login_action(self, username, password):
        # TODO: make an error message for each blacklisted entry
        if self.check_if_in_blacklist_login(username, password) != 0:
            print("data is in blacklist")
            return

        password = self.password_hash(password)
        header = ResponseCodes.LOGIN_HEADER_CODE
        msg = str(username) + Constants.SEPERATOR + str(password)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def create_new_conversation_action(self, name, type):
        header = ResponseCodes.CREATE_NEW_CONVERSATION_HEADER_CODE
        msg = str(name) + Constants.SEPERATOR + str(type)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def select_conversation_from_server_action(self, conversationID):
        header = ResponseCodes.SELECT_CONVERSATION_HEADER_CODE
        msg = conversationID
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def ask_for_rsa_public_key(self):
        header = ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_HEADER_CODE
        msg = "rsapls"
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    # TODO: Support avatar poses and files.
    def send_message(self, converID, text):
        header = ResponseCodes.CLIENT_SENDING_MESSAGE_HEADER_CODE
        msg = converID + Constants.SEPERATOR + text
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def ask_for_old_msgs_action(self, converID, from_msg_id):
        header = ResponseCodes.GET_MESSAGES_HEADER_CODE
        msg = str(converID) + Constants.SEPERATOR + str(from_msg_id)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def handle_packet(self, header, data):
        match header:
            case ResponseCodes.REGIST_SUCCESS_HEADER_CODE:
                print("Successfully registered. Go to login")
                app.show_frame("StartPage")
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
            case ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_SUCCESS_HEADER_CODE:
                public_key = self.commsdata.rsa.bytes_to_key(data.decode())
                self.commsdata.rsa.set_public_key(public_key)
                self.send_aes_key()
            case ResponseCodes.AES_KEY_SUCCESS_HEADER_CODE:
                self.commsdata.encrypted_comms = True
                print("Encrypted communication enabled")
            case ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_FAIL_HEADER_CODE:
                print("failed to receive rsa key")
            case ResponseCodes.CREATE_NEW_CONVERSATION_SUCCESS_HEADER_CODE:
                seperated_data = data.decode().split(Constants.SEPERATOR)
                self.commsdata.update_selected_conversation(id=seperated_data[0], name=seperated_data[1])
                app.frames["ChatPage"].update_selected_conversation()
            case ResponseCodes.CLIENT_SENDING_MESSAGE_SUCCESS_HEADER_CODE:
                print("amazing")
                sep_data = data.decode().split(Constants.SEPERATOR)
                app.frames["ChatPage"].add_message_to_chat(converID=sep_data[0], senderID=sep_data[1], nickname=sep_data[2], text=sep_data[3])
            case ResponseCodes.CLIENT_SENDING_MESSAGE_FAIL_HEADER_CODE:
                print("not amazing")
            case ResponseCodes.SERVER_SENDING_MESSAGE:
                print("amazing")
                sep_data = data.decode().split(Constants.SEPERATOR)
                app.frames["ChatPage"].add_message_to_chat(converID=sep_data[0], senderID=sep_data[2], nickname=sep_data[2],
                                                   text=sep_data[4])
            case ResponseCodes.SELECT_CONVERSATION_SUCCESS_HEADER_CODE:
                converID = data.decode()
                print("conversation " + converID + "selected successfuly")
                self.commsdata.update_selected_conversation(id=converID, name=converID)
                app.frames["ChatPage"].update_selected_conversation()


    def send_aes_key(self):
        header = ResponseCodes.AES_KEY_HEADER_CODE
        key = self.commsdata.aes.get_key()
        msg = self.commsdata.rsa.encrypt(key)
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def password_hash(self, password):
        local_salt = "saltysaltsohot".encode()
        hashed_password = hashlib.pbkdf2_hmac("sha256", password.encode(), local_salt, 100000).hex()
        return hashed_password

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
    REGIST_HEADER_CODE = 110
    REGIST_SUCCESS_HEADER_CODE = 111
    REGIST_FAIL_HEADER_CODE = 112
    REGIST_FAIL_USREXIST_HEADER_CODE = 1121
    REGIST_FAIL_INBLACK_HEADER_CODE = 1122
    LOGIN_HEADER_CODE = 120
    LOGIN_SUCCESS_HEADER_CODE = 121
    LOGIN_FAIL_HEADER_CODE = 122
    LOGIN_FAIL_INBLACK_HEADER_CODE = 1221
    ASK_FOR_RSA_PUBLIC_KEY_HEADER_CODE = 130
    ASK_FOR_RSA_PUBLIC_KEY_SUCCESS_HEADER_CODE = 131
    ASK_FOR_RSA_PUBLIC_KEY_FAIL_HEADER_CODE = 132
    AES_KEY_HEADER_CODE = 140
    AES_KEY_SUCCESS_HEADER_CODE = 141
    AES_KEY_FAIL_HEADER_CODE = 142
    NOTLOGGEDIN_HEADER_CODE = 150
    CREATE_NEW_CONVERSATION_HEADER_CODE = 160
    CREATE_NEW_CONVERSATION_SUCCESS_HEADER_CODE = 161
    CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE = 162
    CREATE_NEW_CONVERSATION_FAIL_ALREADY_EXISTS_HEADER_CODE = 1621
    CLIENT_SENDING_MESSAGE_HEADER_CODE = 170
    CLIENT_SENDING_MESSAGE_SUCCESS_HEADER_CODE = 171
    CLIENT_SENDING_MESSAGE_FAIL_HEADER_CODE = 172
    SERVER_SENDING_MESSAGE = 180
    SELECT_CONVERSATION_HEADER_CODE = 190
    SELECT_CONVERSATION_SUCCESS_HEADER_CODE = 191
    SELECT_CONVERSATION_FAIL_HEADER_CODE = 192
    GET_MESSAGES_HEADER_CODE = 200
    GET_MESSAGES_SUCCESS_HEADER_CODE = 201
    GET_MESSAGES_FAIL_HEADER_CODE = 202


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
                                      command=lambda: threading.Thread(self.controller.servercomms.register_action(
                                          full_name_reg_entry.get(),
                                          email_reg_entry.get(),
                                          phonenum_reg_entry.get(),
                                          username_reg_entry.get(),
                                          password_reg_entry.get())).start())
        back_button = tk.Button(self, text="Back", command=lambda: self.controller.show_frame("StartPage"))
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
    # TODO: Make an working system of displaying chats
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.main_chat_container = tk.Frame(self)
        self.chat_containers = {}

        self.username_label = tk.Label(self, text="Logged in as: ?", font=self.controller.title_font)
        conversation_name_entry = tk.Entry(self, width=60)
        conversation_create_button = tk.Button(self, text="Create new group", command=lambda:
        threading.Thread(self.controller.servercomms.create_new_conversation_action(conversation_name_entry.get(), 1)))
        conversation_select_button = tk.Button(self, text="Select group", command=lambda: threading.Thread(self.controller.servercomms.select_conversation_from_server_action(conversation_name_entry.get())))
        self.selected_conversation_label = tk.Label(self, text="Selected group: ?", font=self.controller.title_font)
        get_more_messages_button = tk.Button(self, text="Get New Messages", command=lambda: threading.Thread(
            self.controller.servercomms.ask_for_old_msgs_action(
                converID=self.controller.servercomms.commsdata.selected_conversation["ID"], from_msg_id=0))) # TODO: Make this automatic
        self.username_label.pack()
        conversation_name_entry.pack()
        conversation_create_button.pack()
        conversation_select_button.pack()
        self.selected_conversation_label.pack()
        get_more_messages_button.pack()

        self.main_chat_container.pack(side="top", fill="both", expand=True)
        self.main_chat_container.grid_rowconfigure(0, weight=1)
        self.main_chat_container.grid_columnconfigure(0, weight=1)

    def update_frame(self):
        self.username_label.configure(text="Logged in as: " + self.controller.servercomms.commsdata.get_nickname())

    def ask_for_messages(self):
        converID = self.controller.servercomms.commsdata.selected_conversation["ID"]
        from_msg_id = self.chat_containers[converID]

    def update_selected_conversation(self):
        self.selected_conversation_label.configure(text="Selected group: " +
                                                        self.controller.servercomms.commsdata.selected_conversation[
                                                            "name"])
        if not self.controller.servercomms.commsdata.selected_conversation["ID"] in self.chat_containers:
            self.chat_containers[self.controller.servercomms.commsdata.selected_conversation["ID"]] = ChatContainer(
                parent=self.main_chat_container, controller=self.controller,
                converID=self.controller.servercomms.commsdata.selected_conversation["ID"])
            self.chat_containers[self.controller.servercomms.commsdata.selected_conversation["ID"]].grid(row=0,
                                                                                                         column=0,
                                                                                                         sticky="nsew")
        self.chat_containers[self.controller.servercomms.commsdata.selected_conversation["ID"]].tkraise()

    def add_message_to_chat(self, converID, senderID, nickname=None, avatar=None, text=None, ctime=None, data=None):
        self.chat_containers[converID].add_message(senderID=senderID, nickname=nickname, avatar=avatar, text=text, ctime=ctime, data=data)


class ChatContainer(tk.Frame):
    def __init__(self, parent, controller, converID):
        tk.Frame.__init__(self, parent, highlightbackground="black", highlightthickness=2)
        self.controller = controller
        self.converID = converID
        self.messages_frame = tk.Frame(self)
        self.message_entry = tk.Entry(self)
        self.message_send_button = tk.Button(self, text="Send",
                                             command=lambda: self.controller.servercomms.send_message(
                                                 converID=self.converID, text=self.message_entry.get()))
        self.messages_frame.pack()
        self.message_entry.pack()
        self.message_send_button.pack()
        self.scrollbar = tk.Scrollbar(self.messages_frame)
        self.scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def add_message(self, senderID, nickname, avatar=None, text=None, ctime=None, data=None):
        if senderID == self.controller.servercomms.commsdata.userId:
            pass # TODO: Position message differently if the user sent it
        MessageContainer(parent=self.messages_frame, controller=self.controller, nickname=nickname, avatar=avatar, text=text, ctime=ctime, data=data).pack()

    def get_oldest_msg_id(self): # TODO: Make the server also send the messageID
        pass

class MessageContainer(tk.Frame):
    # TODO: Create different message layouts according to message type.
    def __init__(self, parent, controller, nickname="test", avatar=None, text=None, ctime=None, data=None):
        tk.Frame.__init__(self, parent, highlightbackground="blue", highlightthickness=2)
        self.controller = controller
        self.msg_sender = tk.Label(self, text=nickname + ":")
        self.msg_text = tk.Label(self, text=text)
        self.msg_sender.pack()
        self.msg_text.pack()


class ServerCommsData:
    def __init__(self):
        # self.salt = None
        self.userId = None
        self.username = None
        self.nickname = None
        self.selected_conversation = {"ID": None, "name": None}
        self.aes = AESEncryption()
        self.rsa = RSAEncryption()
        self.encrypted_comms = False
        self.aes.generate_key()

    def aes(self):
        return self.aes

    def rsa(self):
        return self.rsa

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

    def update_selected_conversation(self, id, name):
        self.selected_conversation["ID"] = id
        self.selected_conversation["name"] = name


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

# TODO: Delete update_frame and instead make an unique def for each updating action.
# TODO: Add character creation system.
# TODO: Yassify the chat: adding hands to the sides of the main window with pink sparking nails. chaning the cursor to a yassified hand.
# TODO: Send to server with packet_len