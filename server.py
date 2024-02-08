##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Server
##############################################################
import os
import traceback
import socket
import threading
import database as database
from enum import IntEnum
from rsa import RSAEncryption
from aes import AESEncryption


clients = []


class Server(object):

    def __init__(self, ip, port):
        self.ip = ip
        self.port = port
        self.count_of_conns = 0
        self.db = database.Users()
        self.clients = []

    def startServer(self):
        try:
            print('server starts up on ip %s port %s' % (self.ip, self.port))
            print(f"active connections: ", self.count_of_conns)

            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.ip, self.port))
            server.listen()

            while True:
                conn, addr = server.accept()
                thread = threading.Thread(target=self.handle_client, args=(conn, addr))
                thread.start()
                print(f"active connections {threading.active_count() - 1}")
        except socket.error as e:
            print(e)

    def handle_client(self, conn, addr):
        print(f"new connection {addr}")
        connected = True
        self.count_of_conns += 1
        client = ClientConnData(conn, addr, self.db)
        self.clients.append(client)
        client.rsa.generate_key()

        while connected:

            try:
                if client.encrypted_comms is True:
                    nonce_len = int(conn.recv(2).decode())
                    nonce = conn.recv(nonce_len)
                    packet = conn.recv(Constants.PACKET_SIZE)
                    decrypted_packet = client.aes.decrypt_data(packet, nonce)
                    decrypted_header = int(decrypted_packet[:Constants.HEADER_LENGTH].decode()) # for now until a proper header protocol is made
                    decrypted_data = decrypted_packet[Constants.HEADER_LENGTH:(Constants.PACKET_SIZE - Constants.HEADER_LENGTH)]
                    print(decrypted_data)
                    print(decrypted_header)
                    print(decrypted_data)
                    self.handle_packet(decrypted_header, decrypted_data, conn, addr, client)
                else:
                    packet_header = int(conn.recv(Constants.HEADER_LENGTH).decode())
                    packet_data = conn.recv(Constants.PACKET_SIZE - Constants.HEADER_LENGTH)
                    self.handle_packet(packet_header, packet_data, conn, addr, client)
            except Exception as error:
                print(traceback.format_exc())
                print(error)
                connected = False

        conn.close()
        self.clients.remove(client)
        self.count_of_conns -= 1
        print("removed client")
        print(self.clients)

    def handle_packet(self, header, data, conn, addr, client):
        match header:
            case ResponseCodes.REGIST_HEADER_CODE:

                try:
                    data_as_list = data.decode().split(Constants.SEPERATOR)

                    if self.check_if_in_blacklist_reg(data_as_list[0], data_as_list[1], data_as_list[2],
                                                      data_as_list[3],
                                                      data_as_list[4]) != 0:
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(
                                                   ResponseCodes.REGIST_FAIL_INBLACK_HEADER_CODE,
                                                   "Failed regist inblack",
                                                   conn, client))
                        snd.start()
                        return

                    if not self.db.check_if_username_exists(data_as_list[3]):
                        self.db.insert_user(data_as_list[0], data_as_list[1], data_as_list[2], data_as_list[3],
                                            data_as_list[4])
                        print("Inserted User Successfuly!")

                        snd = threading.Thread(target=self.send_to_client,
                                               args=(ResponseCodes.REGIST_SUCCESS_HEADER_CODE, "registered beautifully", conn, client))
                        snd.start()

                    else:
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(ResponseCodes.REGIST_FAIL_USREXIST_HEADER_CODE,
                                                     "Failed regist usrnm exist", conn, client))
                        snd.start()

                except Exception as error:
                    print("Did Not insert user!")
                    print(error)
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(ResponseCodes.REGIST_FAIL_HEADER_CODE, "Failed regist", conn, client))
                    snd.start()

                return

            case ResponseCodes.LOGIN_HEADER_CODE:
                try:
                    print("logging in")
                    data_as_list = data.decode().split(Constants.SEPERATOR)
                    clientusername, clientpassword = data_as_list[0], data_as_list[1]
                    print(clientusername,clientpassword)

                    if self.check_if_in_blacklist_login(clientusername, clientpassword) != 0:
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(
                                                   ResponseCodes.LOGIN_FAIL_INBLACK_HEADER_CODE,
                                                   "Failed regist inblack",
                                                   conn, client))
                        snd.start()
                        return

                    serverpassword = self.db.select_userdata_by_username(clientusername, "password")

                    if serverpassword == clientpassword:
                        client.set_user_using_ID(self.db.select_userdata_by_username(clientusername, "userId"))
                        data_response = (str(client.get_userdata("userId")) + Constants.SEPERATOR + client.get_userdata(
                            "fullname") + Constants.SEPERATOR + client.get_userdata("username"))
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(ResponseCodes.LOGIN_SUCCESS_HEADER_CODE, data_response, conn, client))
                        snd.start()

                    else:
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(ResponseCodes.LOGIN_FAIL_HEADER_CODE, "Failed login", conn, client))
                        snd.start()

                except Exception as error:
                    print(traceback.format_exc())
                    print(error)
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(ResponseCodes.LOGIN_FAIL_HEADER_CODE, "Failed login", conn, client))
                    snd.start()

                return

            case ResponseCodes.AES_KEY_HEADER_CODE:
                try:
                    decrypted_key = client.rsa.decrypt(data)
                    client.aes.set_key(decrypted_key)
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(ResponseCodes.AES_KEY_SUCCESS_HEADER_CODE, "Received AES key", conn, client))
                    snd.start()
                    client.encrypted_comms = True
                    print("Encrypted communication enabled")

                except Exception as error:
                    print(error)
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(
                                               ResponseCodes.AES_KEY_FAIL_HEADER_CODE, "Failed to receive AES key",
                                               conn, client))
                    snd.start()

                return

            case ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_HEADER_CODE:
                try:
                    header = ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_SUCCESS_HEADER_CODE
                    public_key = client.rsa.public_key
                    msg = public_key
                    print(msg)
                    print(client.rsa.bytes_to_key(msg))
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(header, msg, conn, client))
                    snd.start()

                except Exception as error:
                    print(error)
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(
                                               ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_FAIL_HEADER_CODE, "Failed to receive RSA public key",
                                               conn, client))
                    snd.start()

                return

    def send_to_client(self, header, msg, conn, client):
        if client.encrypted_comms is True:
            while True:
                header = str(header).zfill(Constants.HEADER_LENGTH).encode()
                if type(msg) is not bytes:
                    msg = msg.encode()

                encrypted_data, nonce = client.aes.encrypt_data(header+msg)
                packet = str(len(nonce)).zfill(2).encode() + nonce + encrypted_data
                print(packet)
                conn.send(packet)
                print("done sending")
                break
        else:
            while True:
                header = str(header).zfill(Constants.HEADER_LENGTH).encode()
                if type(msg) is not bytes:
                    msg = msg.encode()

                packet = header + msg
                print(packet)
                conn.send(packet)
                print("done sending")
                break

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
        if blacklist in password or not len(password) <= 1024:
            return 5
        return 0

    def check_if_in_blacklist_login(self, username, password):
        blacklist = (Constants.SEPERATOR)
        if blacklist in username or not 1 <= len(username) <= 32:
            return 4
        if blacklist in password or not 1 <= len(password) <= 512:
            return 5
        return 0


class ClientConnData:
    def __init__(self, conn, addr, db):
        self.aes = AESEncryption()
        self.rsa = RSAEncryption()
        self.encrypted_comms = False
        self.conn = conn
        self.addr = addr
        self.db = db
        self.userId = None
        self.userdata = {"nickname": None, "email": None, "phonenum": None, "username": None}

    def aes(self):
        return self.aes

    def rsa(self):
        return self.rsa

    def get_conn(self):
        return self.conn

    def get_addr(self):
        return self.addr

    def get_userdata(self, spdata):
        db_userdata = self.db.select_userdata_by_userId(self.userId, spdata)
        return db_userdata

    def set_user_using_ID(self, ID):
        self.userId = ID
        db_userdata = self.db.select_userdata_by_userId(ID, "all")
        self.userdata["nickname"] = db_userdata[1]
        self.userdata["email"] = db_userdata[2]
        self.userdata["phonenum"] = db_userdata[3]
        self.userdata["username"] = db_userdata[4]


class ResponseCodes(IntEnum):
    REGIST_HEADER_CODE = 1
    REGIST_SUCCESS_HEADER_CODE = 11
    REGIST_FAIL_HEADER_CODE = 12
    REGIST_FAIL_USREXIST_HEADER_CODE = 121
    REGIST_FAIL_INBLACK_HEADER_CODE = 122
    LOGIN_HEADER_CODE = 2
    LOGIN_SUCCESS_HEADER_CODE = 21
    LOGIN_FAIL_HEADER_CODE = 22
    LOGIN_FAIL_INBLACK_HEADER_CODE = 221
    ASK_FOR_RSA_PUBLIC_KEY_HEADER_CODE = 3
    ASK_FOR_RSA_PUBLIC_KEY_SUCCESS_HEADER_CODE = 31
    ASK_FOR_RSA_PUBLIC_KEY_FAIL_HEADER_CODE = 32
    AES_KEY_HEADER_CODE = 4
    AES_KEY_SUCCESS_HEADER_CODE = 41
    AES_KEY_FAIL_HEADER_CODE = 42
    NOTLOGGEDIN_HEADER_CODE = 5


class Constants:
    PACKET_SIZE = 1024
    HEADER_LENGTH = 64
    PORT = 8820
    FORMAT = "utf-8"
    SEPERATOR = "█"


def represents_int(data):
    try:
        int(data)
    except ValueError:
        return False
    else:
        return True


class TextMessage:
    pass


class ImageMessage:
    pass


# TODO: Create message queue for sending to users, and classes for each type of message
# TODO: Create response codes for sending messages, and asking to receive queued messeges.
# TODO - done: Implement RSA & AES Encryption on user info and messages.
# TODO: Create a secondary database to store temporary queued messages.
# TODO: Display messages for successful registration and login.

server = Server("127.0.0.1", Constants.PORT)
server.startServer()
