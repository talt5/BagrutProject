##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Client
##############################################################
import io
import sys
import time
import tkinter as tk
from tkinter import font as tkfont
from tkinter import filedialog
from PIL import Image, ImageTk
import threading
import traceback
import socket
import hashlib
import os
import base64
from enum import IntEnum
from rsa import RSAEncryption
from aes import AESEncryption


# TODO URGENT: Compare between checksums of chat image for each chat.
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
                    packet_len = int(self.client.recv(10).decode())
                    print("actual packet len: ", packet_len)
                    bytes_received = 0
                    data = bytearray()
                    while bytes_received < packet_len:
                        if packet_len - bytes_received < 1024:
                            packet = self.client.recv(packet_len - bytes_received)
                            bytes_received = packet_len
                        else:
                            packet = self.client.recv(1024)
                            bytes_received += 1024
                        print("received until now: ", bytes_received)
                        data.extend(packet)
                    decrypted_packet = self.commsdata.aes.decrypt_data(data, nonce)
                    decrypted_header = int(decrypted_packet[:Constants.HEADER_LENGTH].decode())
                    decrypted_data = decrypted_packet[
                                     Constants.HEADER_LENGTH:]
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

    def send_to_server(self, header, msg):
        try:
            if self.commsdata.encrypted_comms is True:
                while self.commsdata.socket_in_use:
                    time.sleep(0.01)
                self.commsdata.socket_in_use = True
                header = str(header).zfill(Constants.HEADER_LENGTH).encode()
                if type(msg) is not bytes:
                    msg = msg.encode()
                print("sending: ".encode() + header + msg)
                encrypted_data, nonce = self.commsdata.aes.encrypt_data(header + msg)
                packet_len = str(len(encrypted_data)).zfill(10).encode()
                print("actual data len: ", packet_len)
                packet = encrypted_data
                self.client.send(str(len(nonce)).zfill(2).encode() + nonce + packet_len)
                packet_sent_len = 0
                packet_len = int(packet_len)
                while packet_sent_len < packet_len:
                    self.client.send(packet[packet_sent_len:packet_sent_len + 1024])
                    packet_sent_len += len(packet[packet_sent_len:packet_sent_len + 1024])
                    print("sent until now: ", packet_sent_len)
                self.commsdata.socket_in_use = False
                print("done sending.")
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

    def create_new_conversation_action(self, name, type, participants, image):
        header = ResponseCodes.CREATE_NEW_CONVERSATION_HEADER_CODE
        msg = str(name) + Constants.SEPERATOR + str(
            type) + Constants.SEPERATOR + participants + Constants.SEPERATOR + image
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

    def send_message(self, converID, text):
        header = ResponseCodes.CLIENT_SENDING_MESSAGE_HEADER_CODE
        msg = converID + Constants.SEPERATOR + text
        snd = threading.Thread(target=self.send_to_server(header, msg))
        snd.start()

    def ask_for_old_msgs_action(self, converID, from_msg_id):
        print(from_msg_id)
        if int(from_msg_id) != 1:
            header = ResponseCodes.GET_MESSAGES_HEADER_CODE
            msg = str(converID) + Constants.SEPERATOR + str(from_msg_id)
            snd = threading.Thread(target=self.send_to_server(header, msg))
            snd.start()

    def delete_message(self, converID, msg_id):
        header = ResponseCodes.DELETE_MESSAGE_HEADER_CODE
        msg = str(converID) + Constants.SEPERATOR + str(msg_id)
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
                sep_data = data.decode().split(Constants.SEPERATOR)
                if int(sep_data[1]) == 1:
                    self.commsdata.update_selected_conversation(id=sep_data[0], name=sep_data[2], image=sep_data[3],
                                                                participants=None)
                elif int(sep_data[1]) == 2:
                    self.commsdata.update_selected_conversation(id=sep_data[0], name=sep_data[2], image=sep_data[3],
                                                                participants=sep_data[4])
                app.frames["ChatPage"].update_selected_conversation()
            case ResponseCodes.CLIENT_SENDING_MESSAGE_SUCCESS_HEADER_CODE:
                print("amazing")
                sep_data = data.decode().split(Constants.SEPERATOR)
                print(sep_data)
                app.frames["ChatPage"].add_message_to_chat(converID=sep_data[0], msg_id=sep_data[1],
                                                           senderID=sep_data[2], nickname=sep_data[2], text=sep_data[3])
                if app.frames["ChatPage"].chat_containers[sep_data[0]].oldest_msg_id > int(sep_data[1]):
                    app.frames["ChatPage"].chat_containers[sep_data[0]].oldest_msg_id = int(sep_data[1])
            case ResponseCodes.CLIENT_SENDING_MESSAGE_FAIL_HEADER_CODE:
                print("not amazing")
            case ResponseCodes.SERVER_SENDING_MESSAGE:
                print("amazing")
                sep_data = data.decode().split(Constants.SEPERATOR)
                print(sep_data)
                app.frames["ChatPage"].add_message_to_chat(converID=sep_data[0], msg_id=sep_data[1],
                                                           senderID=sep_data[2], nickname=sep_data[2],
                                                           text=sep_data[4])
                if app.frames["ChatPage"].chat_containers[sep_data[0]].oldest_msg_id > int(sep_data[1]):
                    app.frames["ChatPage"].chat_containers[sep_data[0]].oldest_msg_id = int(sep_data[1])
            case ResponseCodes.SELECT_CONVERSATION_SUCCESS_HEADER_CODE:
                sep_data = data.decode().split(Constants.SEPERATOR)
                if int(sep_data[1]) == 1:
                    self.commsdata.update_selected_conversation(id=sep_data[0], name=sep_data[2], image=sep_data[3],
                                                                participants=None)
                elif int(sep_data[1]) == 2:
                    self.commsdata.update_selected_conversation(id=sep_data[0], name=sep_data[2], image=sep_data[3],
                                                                participants=sep_data[4])
                app.frames["ChatPage"].update_selected_conversation()
            case ResponseCodes.DELETE_MESSAGE_HEADER_CODE:
                sep_data = data.decode().split(Constants.SEPERATOR)
                app.frames["ChatPage"].chat_containers[sep_data[0]].delete_message(msg_id=sep_data[1])

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
    DELETE_MESSAGE_HEADER_CODE = 210


class App(tk.Tk):
    def __init__(self, *args, **kwargs):
        if not os.path.exists("data"):
            os.makedirs("data")
            os.makedirs("data/default_pictures")
            os.makedirs("data/conversations")

        tk.Tk.__init__(self, *args, **kwargs)
        self.title_font = tkfont.Font(family="Helvetica", size=18, weight="bold")
        self.servercomms = ServerComms("127.0.0.1", Constants.PORT)
        self.servercomms.start()

        container = tk.Frame(self)
        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for Frame in (StartPage, LoginPage, RegistrationPage, ChatPage, ConversationCreationPage):
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
        label = tk.Label(self, text="Welcome to the chat!", font=controller.title_font)
        label.pack(side="top", fill="x", pady=10)

        button1 = tk.Button(self, text="Login",
                            command=lambda: controller.show_frame("LoginPage"))
        button2 = tk.Button(self, text="Register",
                            command=lambda: controller.show_frame("RegistrationPage"))
        button1.pack(pady=10, ipady=15, ipadx=15)
        button2.pack(pady=10, ipady=15, ipadx=15)

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
        username_login_entry.pack(ipady=5, pady=5)
        password_login_entry.pack(ipady=5, pady=5)
        submit_reg_button.pack(ipady=5, pady=5)
        back_button.pack(ipady=5, pady=5)

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
        full_name_reg_entry.pack(ipady=5, pady=5)
        email_reg_entry.pack(ipady=5, pady=5)
        phonenum_reg_entry.pack(ipady=5, pady=5)
        username_reg_entry.pack(ipady=5, pady=5)
        password_reg_entry.pack(ipady=5, pady=5)
        submit_reg_button.pack(ipady=5, pady=5)
        back_button.pack(ipady=5, pady=5)

    def update_frame(self):
        pass


class ConversationCreationPage(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.title_label = tk.Label(self, text="New Conversation", font=self.controller.title_font)
        self.radio_var = tk.IntVar(value=1)
        self.type1_radio = tk.Radiobutton(self, text="Private", variable=self.radio_var, value=1, command=self.sel)
        self.type2_radio = tk.Radiobutton(self, text="Group", variable=self.radio_var, value=2, command=self.sel)
        self.conver_name_entry = tk.Entry(self, width=60)
        self.conver_name_entry.insert(0, "Name")
        self.participants_entry = tk.Entry(self, width=60)
        self.participants_entry.insert(0, "Participants")
        self.photo_path = Constants.DEFAULT_CHAT_PICTURE_PATH
        self.photo = Image.open(self.photo_path)
        self.photo = self.photo.resize((64, 64))
        self.photo = ImageTk.PhotoImage(self.photo)
        self.photo_label = tk.Label(self, image=self.photo)
        self.choose_image_button = tk.Button(self, text="Choose Image For Conversation",
                                             command=self.choose_image_button_action)
        self.create_button = tk.Button(self, text="Create Conversation",
                                       command=lambda: self.create_conver_button_action())

        self.sel()
        self.title_label.pack(ipady=5, pady=5)
        self.type1_radio.pack(ipady=5, pady=5)
        self.type2_radio.pack(ipady=5, pady=5)
        self.photo_label.pack(ipady=5, pady=5)
        self.choose_image_button.pack(ipady=5, pady=5)
        self.conver_name_entry.pack(ipady=5, pady=5)
        self.participants_entry.pack(ipady=5, pady=5)
        self.create_button.pack(ipady=5, pady=5)

    def sel(self):
        if self.radio_var.get() == 3:
            self.conver_name_entry.configure(state=tk.DISABLED)
            self.photo_label.configure(state=tk.DISABLED)
            self.choose_image_button.configure(state=tk.DISABLED)
        if self.radio_var.get() == 2:
            self.conver_name_entry.configure(state=tk.NORMAL)
            self.photo_label.configure(state=tk.NORMAL)
            self.choose_image_button.configure(state=tk.NORMAL)

    def choose_image_button_action(self):
        filetypes = (("Image files", "*.png"), ("All files", "*.*"))
        filename = tk.filedialog.askopenfilename(title="Choose an image", filetypes=filetypes)
        if filename:
            self.change_photo(photo_path=filename)

    def change_photo(self, photo_path):
        self.photo = Image.open(self.photo_path)
        self.photo = self.photo.resize((64, 64))
        self.photo = ImageTk.PhotoImage(self.photo)
        self.photo_label.configure(image=self.photo)
        self.photo_label.imgref = self.photo
        self.photo_path = photo_path
        self.controller.update()

    def create_conver_button_action(self):
        with open(self.photo_path, "rb") as img:
            image = base64.b64encode(img.read()).decode()
        self.controller.servercomms.create_new_conversation_action(name=self.conver_name_entry.get(),
                                                                   type=self.radio_var.get(),
                                                                   participants=self.participants_entry.get(),
                                                                   image=image)
        self.controller.show_frame("ChatPage")
        # Read image data and convert it to BASE64 string. Then call create_new_conver from servercomms.

    def update_frame(self):
        pass


class ChatPage(tk.Frame):
    # TODO: Make an working system of displaying chats
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.main_chat_container = tk.Frame(self)
        self.chat_containers = {}
        self.chat_selection_buttons = {}

        self.username_label = tk.Label(self, text="Logged in as: ?", font=self.controller.title_font)
        create_conver_button = tk.Button(self, text="Create new conversation",
                                         command=lambda: self.controller.show_frame("ConversationCreationPage"))
        self.username_label.pack(ipady=5, pady=5)
        create_conver_button.pack(ipady=5, pady=5)

        self.main_chat_container.pack(side="top", fill="both", expand=True)
        self.main_chat_container.grid_rowconfigure(0, weight=1)
        self.main_chat_container.grid_columnconfigure(0, weight=1)

    def update_frame(self):
        self.username_label.configure(text="Logged in as: " + self.controller.servercomms.commsdata.get_nickname())

    def update_selected_conversation(self):
        commsdata = self.controller.servercomms.commsdata
        if not commsdata.selected_conversation["ID"] in self.chat_containers:
            self.chat_containers[commsdata.selected_conversation["ID"]] = ChatContainer(
                parent=self.main_chat_container, controller=self.controller,
                converID=commsdata.selected_conversation["ID"],
                conver_name=commsdata.selected_conversation["name"],
                conver_image=commsdata.selected_conversation["image"],
                participants=commsdata.selected_conversation["participants"])
            self.chat_containers[commsdata.selected_conversation["ID"]].grid(row=0,
                                                                             column=0,
                                                                             sticky="nsew")
            self.chat_selection_buttons[
                commsdata.selected_conversation["ID"]] = ChatSelectionButton(parent=self,
                                                                             controller=self.controller,
                                                                             converID=
                                                                             commsdata.selected_conversation[
                                                                                 "ID"],
                                                                             conver_name=
                                                                             commsdata.selected_conversation[
                                                                                 "name"], conver_image=
                                                                             commsdata.selected_conversation["image"])
            self.chat_selection_buttons[commsdata.selected_conversation["ID"]].pack(side=tk.LEFT)
        self.chat_containers[commsdata.selected_conversation["ID"]].tkraise()

    def add_message_to_chat(self, converID, msg_id, senderID, nickname=None, avatar=None, text=None, ctime=None,
                            data=None):
        self.chat_containers[converID].add_message(msg_id=msg_id, senderID=senderID, nickname=nickname, avatar=avatar,
                                                   text=text, ctime=ctime, data=data)


class ChatSelectionButton(tk.Button):
    def __init__(self, parent, controller, converID, conver_name, conver_image):
        self.controller = controller
        self.converID = converID
        self.conver_name = conver_name
        self.photo = Image.open(io.BytesIO(base64.b64decode(conver_image)))
        self.photo = self.photo.resize((64, 64))
        self.photo = ImageTk.PhotoImage(self.photo)
        tk.Button.__init__(self, parent, image=self.photo, text=conver_name, command=self.select_conversation,
                           compound=tk.LEFT)

    def select_conversation(self):
        self.controller.servercomms.commsdata.update_selected_conversation(id=self.converID, name=self.conver_name,
                                                                           image=self.photo)
        self.controller.frames["ChatPage"].update_selected_conversation()


class ChatContainer(tk.Frame):
    def __init__(self, parent, controller, converID, conver_name, conver_image=None, participants=None):
        tk.Frame.__init__(self, parent, highlightbackground="black", highlightthickness=2)
        self.controller = controller
        self.converID = converID
        self.conver_name = conver_name
        self.oldest_msg_id = sys.maxsize
        self.conver_header = ChatHeaderContainer(parent=self, controller=self.controller, converID=self.converID,
                                                 conver_name=self.conver_name,
                                                 picture=conver_image, participants=participants)
        self.canvas = tk.Canvas(self, borderwidth=0)
        self.messages_frame = tk.Frame(self.canvas)
        self.messages_frame.columnconfigure(1, weight=1)
        self.messages_frame.columnconfigure(2, weight=1)
        self.vsb = tk.Scrollbar(self, orient=tk.VERTICAL, command=self.canvas.yview, jump=True)
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side=tk.RIGHT, fill=tk.Y)
        self.xsb = tk.Scrollbar(self, orient=tk.HORIZONTAL, command=self.canvas.xview)
        self.canvas.configure(xscrollcommand=self.xsb.set)
        self.xsb.pack(side=tk.BOTTOM, fill=tk.X)
        self.canvas.create_window((4, 4), window=self.messages_frame, anchor=tk.N, tags="self.messages_frame")
        self.messages_frame.bind("<Configure>", self.onFrameConfigure)
        self.message_entry = tk.Entry(self)
        self.message_send_button = tk.Button(self, text="Send",
                                             command=lambda: self.controller.servercomms.send_message(
                                                 converID=self.converID, text=self.message_entry.get()))
        self.get_more_messages_button = tk.Button(self.messages_frame, text="Get New Messages",
                                                  command=lambda: self.controller.servercomms.ask_for_old_msgs_action(
                                                      converID=self.converID, from_msg_id=self.oldest_msg_id))
        self.get_more_messages_button.grid(row=0, column=1, sticky=tk.W)
        self.conver_header.pack(fill=tk.X)
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self.message_entry.pack()
        self.message_send_button.pack()

        self.controller.servercomms.ask_for_old_msgs_action(converID=self.converID, from_msg_id=0)

    def onFrameConfigure(self, event):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def add_message(self, msg_id, senderID, nickname, avatar=None, text=None, ctime=None, data=None):
        msg = MessageContainer(parent=self.messages_frame, controller=self.controller, converID=self.converID,
                               sender_id=senderID,
                               msg_id=msg_id, nickname=nickname, avatar=avatar, text=text, ctime=ctime, data=data)
        if senderID == self.controller.servercomms.commsdata.userId:
            msg.grid(row=int(msg_id) + 2, column=1, sticky=tk.W, pady=5)
        else:
            msg.grid(row=int(msg_id) + 2, column=1, sticky=tk.W, pady=5)

    def delete_message(self, msg_id):
        self.messages_frame.grid_slaves(row=int(msg_id) + 2, column=1)[0].destroy()
        del_msg = tk.Label(self.messages_frame, text="Deleted message")
        del_msg.grid(row=int(msg_id) + 2, column=1, sticky=tk.W)


class ChatHeaderContainer(tk.Frame):
    def __init__(self, parent, controller, converID, conver_name, picture, participants):
        tk.Frame.__init__(self, parent, highlightbackground="black", highlightthickness=2)
        self.controller = controller
        self.photo = Image.open(io.BytesIO(base64.b64decode(picture)))
        self.photo = self.photo.resize((64, 64))
        self.photo = ImageTk.PhotoImage(self.photo)
        self.conver_picture_label = tk.Label(self, image=self.photo)
        self.name_label = tk.Label(self, text=conver_name, font=("MS Sans Serif", "16", "bold"))
        self.participants_label = tk.Label(self, text=participants)
        self.conver_picture_label.grid(row=1, column=1, rowspan=2, sticky=tk.W)
        self.name_label.grid(row=1, column=2, sticky=tk.W)
        self.participants_label.grid(row=2, column=2, sticky=tk.W)


class MessageContainer(tk.Frame):
    # TODO: Create different message layouts according to message type.
    def __init__(self, parent, controller, converID, msg_id, sender_id, nickname="test", avatar=None, text=None,
                 ctime=None,
                 data=None):
        tk.Frame.__init__(self, parent, highlightbackground="blue", highlightthickness=1)
        self.controller = controller
        self.converID = converID
        self.msg_id = msg_id
        self.msg_sender = sender_id
        self.msg_senderw = tk.Label(self, text=nickname)
        self.msg_textw = tk.Label(self, text=text)
        if self.msg_sender == self.controller.servercomms.commsdata.userId:
            self.msg_senderw.pack(side=tk.LEFT)
            self.msg_textw.pack()
        else:
            self.msg_senderw.pack(side=tk.LEFT)
            self.msg_textw.pack()

        self.rc_menu = tk.Menu(self, tearoff=0)
        self.rc_menu.add_command(label="Info")  # Popup with info
        self.rc_menu.add_separator()
        self.rc_menu.add_command(label="Copy")  # Copies to clipboard
        self.rc_menu.add_separator()
        self.rc_menu.add_command(label="Delete", command=self.delete_action)  # Deletes message
        self.msg_textw.bind("<Button-3>", self.do_popup)

    def do_popup(self, event):
        print("gay")
        try:
            self.rc_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.rc_menu.grab_release()

    def delete_action(self):
        self.controller.servercomms.delete_message(converID=self.converID, msg_id=self.msg_id)


class ServerCommsData:
    def __init__(self):
        # self.salt = None
        self.userId = None
        self.username = None
        self.nickname = None
        self.selected_conversation = {"ID": None, "name": None, "image": None, "participants": None}
        self.aes = AESEncryption()
        self.rsa = RSAEncryption()
        self.encrypted_comms = False
        self.aes.generate_key()
        self.socket_in_use = False

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

    def update_selected_conversation(self, id, name, image, participants=None):
        self.selected_conversation["ID"] = id
        self.selected_conversation["name"] = name
        self.selected_conversation["image"] = image
        self.selected_conversation["participants"] = participants


class Constants:
    PACKET_SIZE = 1024
    HEADER_LENGTH = 64
    SERVER = "127.0.0.1"
    PORT = 8820
    FORMAT = "utf-8"
    SEPERATOR = "█"
    DEFAULT_CHAT_PICTURE_PATH = "data/default_pictures/default_chat_picture.png"


if __name__ == "__main__":
    app = App()
    app.mainloop()

# TODO: Delete update_frame and instead make an unique def for each updating action.
# TODO: Add character creation system.
# TODO: Yassify the chat: adding hands to the sides of the main window with pink sparking nails. chaning the cursor to a yassified hand.
