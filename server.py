##############################################################
# Tal Trakhtenberg
# Mesima register login
# 03.01.2024
# Server
##############################################################
import os
import socket
import threading
import database as database
import hashlib
from enum import IntEnum
from cryptography.fernet import Fernet

PACKET_SIZE = 1024
HEADER_LENGTH = 64

PORT = 8820
SERVER = socket.gethostbyname(socket.gethostname())
ADDRESS = (SERVER, PORT)
FORMAT = "utf-8"
SEPERATOR = "█"

clients = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(ADDRESS)
db = database.Users()

server_salt = None


def startServer():
    print("server is working on " + SERVER)
    print(f"active connections {threading.active_count() - 1}")
    server.listen()
    while True:
        conn, addr = server.accept()
        clients.append(conn)
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()
        print(f"active connections {threading.active_count() - 1}")


def handle_client(conn, addr):
    print(f"new connection {addr}")
    connected = True
    while connected:
        try:
            packet_header = int(conn.recv(HEADER_LENGTH).decode())
            packet_data = conn.recv(PACKET_SIZE - HEADER_LENGTH)
            handle_packet(packet_header, packet_data, conn, addr)
        except Exception as error:
            print(error)
            connected = False
    conn.close()

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
    ASK_FOR_SALT_HEADER_CODE = 3
    ASK_FOR_SALT_FAIL_HEADER_CODE = 32

def handle_packet(header, data, conn, addr):
    global server_salt
    match header:
        case ResponseCodes.REGIST_HEADER_CODE:
            try:
                data_as_list = data.decode().split(SEPERATOR)
                f = Fernet(server_salt)
                data_as_list[4] = f.decrypt(data_as_list[4]).decode()
                server_salt = None
                if check_if_in_blacklist_reg(data_as_list[0], data_as_list[1], data_as_list[2], data_as_list[3],
                                             data_as_list[4]) != 0:
                    snd = threading.Thread(target=send_to_client,
                                           args=(ResponseCodes.REGIST_FAIL_INBLACK_HEADER_CODE, "Failed regist inblack", conn))
                    snd.start()
                    return
                if not db.check_if_username_exists(data_as_list[3]):
                    db.insert_user(data_as_list[0], data_as_list[1], data_as_list[2], data_as_list[3], data_as_list[4])
                    db.select_all()
                    print("Inserted User Successfuly!")
                    snd = threading.Thread(target=send_to_client, args=(ResponseCodes.REGIST_SUCCESS_HEADER_CODE, "Success regist", conn))
                    snd.start()
                else:
                    snd = threading.Thread(target=send_to_client,
                                           args=(ResponseCodes.REGIST_FAIL_USREXIST_HEADER_CODE, "Failed regist usrnm exist", conn))
                    snd.start()
            except Exception as error:
                server_salt = None
                print("Did Not insert user!")
                print(error)
                snd = threading.Thread(target=send_to_client, args=(ResponseCodes.REGIST_FAIL_HEADER_CODE, "Failed regist", conn))
                snd.start()
            return

        case ResponseCodes.LOGIN_HEADER_CODE:
            try:
                data_as_list = data.decode().split(SEPERATOR)
                f = Fernet(server_salt)
                clientusername, clientpassword = data_as_list[0], data_as_list[1]
                if check_if_in_blacklist_login(clientusername, clientpassword) != 0:
                    snd = threading.Thread(target=send_to_client,
                                           args=(ResponseCodes.LOGIN_FAIL_INBLACK_HEADER_CODE, "Failed regist inblack", conn))
                    snd.start()
                    return
                clientpassword = f.decrypt(clientpassword).decode()
                serverpassword = db.select_userdata_by_username(clientusername, "password")
                server_salt = None
                if serverpassword == clientpassword:
                    snd = threading.Thread(target=send_to_client, args=(ResponseCodes.LOGIN_SUCCESS_HEADER_CODE, "Success login", conn))
                    snd.start()
                else:
                    snd = threading.Thread(target=send_to_client, args=(ResponseCodes.LOGIN_FAIL_HEADER_CODE, "Failed login", conn))
                    snd.start()
            except Exception as error:
                server_salt = None
                print(error)
                snd = threading.Thread(target=send_to_client, args=(ResponseCodes.LOGIN_FAIL_HEADER_CODE, "Failed login", conn))
                snd.start()
            return

        case ResponseCodes.ASK_FOR_SALT_HEADER_CODE:
            try:
                server_salt = Fernet.generate_key().decode()
                snd = threading.Thread(target=send_to_client, args=(ResponseCodes.ASK_FOR_SALT_HEADER_CODE, server_salt, conn))
                snd.start()
            except Exception as error:
                print(error)
                snd = threading.Thread(target=send_to_client,
                                       args=(ResponseCodes.ASK_FOR_SALT_FAIL_HEADER_CODE, "Failed to create salt", conn))
                snd.start()
            return


def send_to_client(header, msg, conn):
    while True:
        header = str(header).zfill(HEADER_LENGTH)
        msg = str(msg)
        packet = header + msg
        print(packet)
        conn.send(packet.encode())
        print("done sending")
        break


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
    if blacklist in password or not len(password) <= 1024:
        return 5
    return 0


def check_if_in_blacklist_login(username, password):
    blacklist = (SEPERATOR)
    if blacklist in username or not 1 <= len(username) <= 32:
        return 4
    if blacklist in password or not 1 <= len(password) <= 1024:
        return 5
    return 0


def represents_int(data):
    try:
        int(data)
    except ValueError:
        return False
    else:
        return True


startServer()
