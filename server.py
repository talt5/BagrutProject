import os
import traceback
import socket
import threading
import time
import database as database
import messagedb
import messagedb as meesagedb
import userdb as userdb
import conversationsdb as conversationsdb
from enum import IntEnum
from rsa import RSAEncryption
from aes import AESEncryption



class Server(object):

    def __init__(self, ip, port):
        if not os.path.exists("db"):
            os.makedirs("db")
            os.makedirs("db/conversations")
            os.makedirs("db/users")
        if not os.path.exists("db/conversations"):
            os.makedirs("db/conversations")
        if not os.path.exists("db/users"):
            os.makedirs("db/users")

        self.ip = ip
        self.port = port
        self.count_of_conns = 0
        self.db = database.Users()
        self.lock = threading.Lock()
        self.allconversationsdb = conversationsdb.Conversations()
        self.clients = []  # Make it a dictionary for efficiency
        self.logged_in_clients = {}

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
                    packet_len = int(conn.recv(10).decode())
                    print("actual packet len: ", packet_len)
                    bytes_received = 0
                    data = bytearray()
                    while bytes_received < packet_len:
                        if packet_len - bytes_received < 1024:
                            packet = conn.recv(packet_len - bytes_received)
                            bytes_received = packet_len
                        else:
                            packet = conn.recv(1024)
                            bytes_received += 1024
                        print("received until now: ", bytes_received)
                        data.extend(packet)
                    decrypted_packet = client.aes.decrypt_data(data, nonce)
                    decrypted_header = int(decrypted_packet[:Constants.HEADER_LENGTH].decode())
                    decrypted_data = decrypted_packet[
                                     Constants.HEADER_LENGTH:]
                    print("received: ".encode() + decrypted_data)
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
        if client.userId in self.logged_in_clients:
            self.logged_in_clients.pop(client.userId)
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
                                            data_as_list[4], data_as_list[5])
                        print("Inserted User Successfuly!")
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(
                                                   ResponseCodes.REGIST_SUCCESS_HEADER_CODE, "registered beautifully",
                                                   conn,
                                                   client))
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
                    print(clientusername, clientpassword)
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
                        userId = self.db.select_userdata_by_username(clientusername, "userId")
                        client.set_user_using_ID(userId)
                        data_response = (str(client.get_userdata("userId")) + Constants.SEPERATOR + client.get_userdata(
                            "fullname") + Constants.SEPERATOR + client.get_userdata("username")) # TODO: Send profile picture.
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(
                                                   ResponseCodes.LOGIN_SUCCESS_HEADER_CODE, data_response, conn,
                                                   client))
                        snd.start()
                        self.send_to_user_all_his_convers(client)
                        self.logged_in_clients[userId] = client
                    else:
                        snd = threading.Thread(target=self.send_to_client,
                                               args=(
                                                   ResponseCodes.LOGIN_FAIL_HEADER_CODE, "Failed login", conn, client))
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
                                           args=(
                                               ResponseCodes.AES_KEY_SUCCESS_HEADER_CODE, "Received AES key", conn,
                                               client))
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
                                               ResponseCodes.ASK_FOR_RSA_PUBLIC_KEY_FAIL_HEADER_CODE,
                                               "Failed to receive RSA public key",
                                               conn, client))
                    snd.start()
                return

            case ResponseCodes.CREATE_NEW_CONVERSATION_HEADER_CODE:
                try:
                    seperated_data = data.decode().split(Constants.SEPERATOR)
                    if int(seperated_data[1]) == 1:  # if type = 1 - private conversation
                        secondID = self.db.select_userdata_by_username(username=seperated_data[2], spdata="userId")
                        if not secondID:
                            header = ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE
                            msg = "given user does not exist"
                            snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                            snd.start()
                            return
                        firstID = client.userId
                        conver_name = str(firstID) + str(secondID)
                        converID, conver_name = self.allconversationsdb.create_new_conversation(name=conver_name,
                                                                                                contype=1, creatorID=firstID, secUserID=secondID)
                        conver_name = self.db.select_userdata_by_userId(userId=secondID, spdata="fullname")
                        conver_image = self.db.select_userdata_by_userId(userId=secondID, spdata="profilepic")
                        if converID is not None:
                            client.userdb.add_conversation(converID)
                            userdb.User(secondID).add_conversation(converID)
                            mdb = messagedb.Conversation(converID)
                            mdb.insert_participant(userID=firstID, isadmin=1)
                            mdb.insert_participant(userID=secondID, isadmin=1)
                            header = ResponseCodes.CREATE_NEW_CONVERSATION_SUCCESS_HEADER_CODE
                            msg = str(converID) + Constants.SEPERATOR + seperated_data[1] + Constants.SEPERATOR + conver_name + Constants.SEPERATOR + conver_image
                            snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                            snd.start()
                            second_client = None
                            if secondID in self.logged_in_clients:
                                second_client = self.logged_in_clients[secondID]
                            if second_client:
                                self.send_to_user_a_conver(converID=converID, client=second_client)
                        else:
                            header = ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE
                            msg = "already exists"
                            snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                            snd.start()
                    elif int(seperated_data[1]) == 2: # if type = 2 - group conversation
                        usernames = seperated_data[2].split(',')
                        userIDs = []
                        for username in usernames:
                            userID = self.db.select_userdata_by_username(username=username, spdata="userId")
                            if not userID:
                                header = ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE
                                msg = "username: " + username + " does not exist. Did not add them to conversation."
                                snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                                snd.start()
                                continue
                            if client.userId == userID:
                                continue
                            userIDs.append(userID)
                        creatorID = client.userId
                        conver_name = seperated_data[0]
                        converID, conver_name, conver_image = self.allconversationsdb.create_new_conversation(name=conver_name, contype=2, creatorID=creatorID, secUserID=None, image=seperated_data[3])
                        if converID is not None:
                            client.userdb.add_conversation(converID)
                            mdb = messagedb.Conversation(converID)
                            mdb.insert_participant(userID=creatorID, isadmin=1)
                            for userID in userIDs:
                                mdb.insert_participant(userID=userID, isadmin=0)
                                userdb.User(userID).add_conversation(converID)
                                if userID in self.logged_in_clients:
                                    second_client = self.logged_in_clients[userID]
                                    self.send_to_user_a_conver(converID=converID, client=second_client)
                            self.send_to_user_a_conver(converID=converID, client=client)
                        else:
                            header = ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE
                            msg = "an error has occurred while creating conver"
                            snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                            snd.start()
                    else:
                        header = ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE
                        msg = "something happened"
                        snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                        snd.start()
                except Exception as error:
                    print(traceback.format_exc())
                    snd = threading.Thread(target=self.send_to_client,
                                           args=(
                                               ResponseCodes.CREATE_NEW_CONVERSATION_FAIL_HEADER_CODE,
                                               "Failed to create a new conversation",
                                               conn, client))
                    snd.start()

            case ResponseCodes.CLIENT_SENDING_MESSAGE_HEADER_CODE:
                # TODO: Check that client didn't add seperators in message
                try:
                    seperated_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=seperated_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        msgID = mdb.insert_message(sender=client.userId, msgtype=1, text=seperated_data[1])
                        snd = threading.Thread(self.send_message_to_all_online_conver_participants(converID=seperated_data[0], messageID=msgID))
                        snd.start()
                    else:
                        header = ResponseCodes.CLIENT_SENDING_MESSAGE_FAIL_HEADER_CODE
                        msg = "User not participating in this chat!"
                        snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                        snd.start()
                except Exception as error:
                    print(error)
                    header = ResponseCodes.CLIENT_SENDING_MESSAGE_FAIL_HEADER_CODE
                    msg = "User not participating in this chat!"
                    snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                    snd.start()

            case ResponseCodes.GET_MESSAGES_HEADER_CODE:
                try:
                    sep_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=sep_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        self.send_to_user_older_messages(converID=sep_data[0], from_msg_id=sep_data[1], client=client)
                except Exception as error:
                    print(error)

            case ResponseCodes.DELETE_MESSAGE_HEADER_CODE:
                try:
                    sep_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=sep_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        if mdb.check_if_user_is_admin(userID=client.userId):
                            self.delete_message(converID=sep_data[0], messageID=sep_data[1])
                        elif mdb.get_message(messageID=sep_data[1])[1] == client.userId:
                            self.delete_message(converID=sep_data[0], messageID=sep_data[1])
                except Exception as error:
                    print(traceback.format_exc())

            case ResponseCodes.UPDATE_CONVERSATION_DATA_HEADER_CODE:
                try:
                    sep_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=sep_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        if mdb.check_if_user_is_admin(userID=client.userId):
                            self.update_conversation_data(converID=sep_data[0], type=sep_data[1], data=sep_data[2])
                except Exception as error:
                    print(traceback.format_exc())
            case ResponseCodes.LEAVE_CONVERSATION_HEADER_CODE:
                try:
                    sep_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=sep_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        del mdb
                        self.remove_participant(converID=sep_data[0], userID=client.userId)
                except Exception as error:
                    print(traceback.format_exc())
            case ResponseCodes.REMOVE_PARTICIPANT_HEADER_CODE:
                try:
                    sep_data = data.decode().split(Constants.SEPERATOR)
                    mdb = messagedb.Conversation(conversationID=sep_data[0])
                    if mdb.check_if_user_is_participating(client.userId):
                        if mdb.check_if_user_is_admin(userID=client.userId):
                            del mdb
                            if int(sep_data[1]) != client.userId:
                                if int(sep_data[1]) == 0:
                                    self.remove_participant(converID=sep_data[0], userID=0)
                                else:
                                    self.remove_participant(converID=sep_data[0], userID=sep_data[1])
                            else:
                                header = ResponseCodes.REMOVE_PARTICIPANT_FAILED_HEADER_CODE
                                msg = "Use 'Leave Conversation' button in order to remove yourself."
                                snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                                snd.start()
                        else:
                            header = ResponseCodes.REMOVE_PARTICIPANT_FAILED_HEADER_CODE
                            msg = "You are not an admin."
                            snd = threading.Thread(target=self.send_to_client, args=(header, msg, conn, client))
                            snd.start()
                except Exception as error:
                    print(traceback.format_exc())
            case ResponseCodes.GET_PARTICIPANTS_HEADER_CODE:
                sep_data = data.decode().split(Constants.SEPERATOR)
                self.send_all_participants_data(converID=sep_data[0], client=client)


    def send_to_user_all_his_convers(self, client):
        try:
            user_conversations = client.userdb.get_all_convers()
            if user_conversations is not None:
                for converID in user_conversations:
                    converID = converID[0]
                    self.send_to_user_a_conver(converID=converID, client=client)
        except Exception as error:
            print(traceback.format_exc())

    def send_to_user_a_conver(self, converID, client):
        try:
            header = ResponseCodes.SELECT_CONVERSATION_SUCCESS_HEADER_CODE
            mdb = messagedb.Conversation(conversationID=converID)
            conver_type = self.allconversationsdb.get_conver_spdata_by_id(converID=converID, spdata="conversationtype")
            if conver_type == 1:
                second_userId = mdb.get_all_participant_ids()
                second_userId.remove(client.userId)
                second_userId = second_userId[0]
                second_name = self.db.select_userdata_by_userId(userId=second_userId, spdata="fullname")
                conver_image = self.db.select_userdata_by_userId(userId=second_userId, spdata="profilepic")
                msg = str(converID) + Constants.SEPERATOR + str(conver_type) + Constants.SEPERATOR + second_name + Constants.SEPERATOR + conver_image
                snd = threading.Thread(target=self.send_to_client, args=(header, msg, client.conn, client))
                snd.start()
            elif conver_type == 2:
                userIds = mdb.get_all_participant_ids()
                participants_names = ""
                for userID in userIds:
                    second_name = self.db.select_userdata_by_userId(userId=userID, spdata="fullname")
                    participants_names = ", ".join([participants_names, second_name])
                participants_names = participants_names[1:]  # to delete the first comma
                conver_image = self.allconversationsdb.get_conver_spdata_by_id(converID=converID,
                                                                               spdata="conversationimage")
                conver_name = self.allconversationsdb.get_conver_spdata_by_id(converID=converID,
                                                                              spdata="conversationname")
                msg = str(converID) + Constants.SEPERATOR + str(
                    conver_type) + Constants.SEPERATOR + conver_name + Constants.SEPERATOR + conver_image + Constants.SEPERATOR + participants_names
                snd = threading.Thread(target=self.send_to_client, args=(header, msg, client.conn, client))
                snd.start()
        except Exception as error:
            print(error)

    def send_to_user_older_messages(self, converID, from_msg_id, client):
        try:
            from_msg_id = int(from_msg_id)
            mdb = messagedb.Conversation(conversationID=converID)
            if from_msg_id != 0:
                for i in range(15):
                    self.send_message_to_client(converID=converID, messageID=(from_msg_id - i), client=client)
            else:
                from_msg_id = mdb.get_last_message_id()
                if from_msg_id < 15:
                    for i in range(from_msg_id):
                        self.send_message_to_client(converID=converID, messageID=(from_msg_id - i), client=client)
                else:
                    for i in range(15):
                        self.send_message_to_client(converID=converID, messageID=(from_msg_id - i), client=client)
        except Exception as error:
            print(error)

    def send_message_to_all_online_conver_participants(self, converID, messageID):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            participants = mdb.get_all_participant_ids()
            for userID in participants:
                if userID in self.logged_in_clients:
                    print("sending to " + str(userID))
                    self.send_message_to_client(converID=converID, messageID=messageID, client=self.logged_in_clients[userID])
        except Exception as error:
            print(error)

    def delete_message(self, converID, messageID):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            mdb.delete_message(messageID=messageID)
            participants = mdb.get_all_participant_ids()
            header = ResponseCodes.DELETE_MESSAGE_HEADER_CODE
            for userID in participants:
                if userID in self.logged_in_clients:
                    msg = str(converID) + Constants.SEPERATOR + str(messageID)
                    snd = threading.Thread(target=self.send_to_client, args=(header, msg, self.logged_in_clients[userID].conn, self.logged_in_clients[userID]))
                    snd.start()
        except Exception as error:
            print(traceback.format_exc())

    def send_all_participants_data(self, converID, client):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            prtc_ids = mdb.get_all_participant_ids()
            for userID in prtc_ids:
                self.send_participant_data(converID=converID, userID=userID, client=client)
        except Exception as error:
            print(traceback.format_exc())


    def send_participant_data(self, converID, userID, client):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            if mdb.check_if_user_is_participating(userID=userID) and mdb.check_if_user_is_participating(userID=client.userId):
                header = ResponseCodes.GET_PARTICIPANT_SUCCESS_HEADER_CODE
                msg = str(converID) + Constants.SEPERATOR + str(userID) + Constants.SEPERATOR + self.db.select_userdata_by_userId(userId=userID, spdata="username") + Constants.SEPERATOR + self.db.select_userdata_by_userId(userId=userID, spdata="fullname") + Constants.SEPERATOR + self.db.select_userdata_by_userId(userId=userID, spdata="profilepic")
                snd = threading.Thread(target=self.send_to_client, args=(header, msg, client.conn, client))
                snd.start()
        except Exception as error:
            print(traceback.format_exc())

    def remove_participant(self, converID, userID):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            participants = mdb.get_all_participant_ids()
            if userID == 0:
                mdb.remove_participant(userID=0)
                self.remove_conversation(converID=converID)
                del mdb
                for e_userID in participants:
                    userdb.User(userID=e_userID).remove_participancy(conversationID=converID)
                    if e_userID in self.logged_in_clients:
                        header = ResponseCodes.REMOVE_PARTICIPANT_SUCCESS_HEADER_CODE
                        msg = str(converID) + Constants.SEPERATOR + str(e_userID)
                        snd = threading.Thread(target=self.send_to_client, args=(
                        header, msg, self.logged_in_clients[e_userID].conn, self.logged_in_clients[e_userID]))
                        snd.start()
            else:
                mdb.remove_participant(userID=userID)
                userdb.User(userID=userID).remove_participancy(conversationID=converID)
                prtc_after_removal = mdb.get_all_participant_ids()
                del mdb
                if not prtc_after_removal:
                    self.remove_conversation(converID=converID)
                for e_userID in participants:
                    if e_userID in self.logged_in_clients:
                        header = ResponseCodes.REMOVE_PARTICIPANT_SUCCESS_HEADER_CODE
                        msg = str(converID) + Constants.SEPERATOR + str(userID)
                        snd = threading.Thread(target=self.send_to_client, args=(
                        header, msg, self.logged_in_clients[e_userID].conn, self.logged_in_clients[e_userID]))
                        snd.start()
        except Exception as error:
            print(traceback.format_exc())

    def remove_conversation(self, converID):
        try:
            self.allconversationsdb.remove_conversation(converID=converID)
            os.remove("db/conversations/" + str(converID) + ".db")
        except:
            print(traceback.format_exc())

    def update_conversation_data(self, converID, type, data):
        try:
            type = int(type)
            if type == 1:  # Name change
                self.allconversationsdb.change_conver_info(converID=converID, info=data, spdata="conversationname")
            elif type == 2:  # Photo change
                self.allconversationsdb.change_conver_info(converID=converID, info=data, spdata="conversationimage")
            header = ResponseCodes.UPDATE_CONVERSATION_DATA_SUCCESS_HEADER_CODE
            msg = str(converID) + Constants.SEPERATOR + str(type) + Constants.SEPERATOR + str(data)
            mdb = messagedb.Conversation(conversationID=converID)
            participants = mdb.get_all_participant_ids()
            for userID in participants:
                if userID in self.logged_in_clients:
                    snd = threading.Thread(target=self.send_to_client, args=(
                    header, msg, self.logged_in_clients[userID].conn, self.logged_in_clients[userID]))
                    snd.start()
        except Exception as error:
            print(traceback.format_exc())

    def send_message_to_client(self, converID, messageID, client):
        try:
            mdb = messagedb.Conversation(conversationID=converID)
            message = mdb.get_message(messageID=messageID)
            print(message)
            header = ResponseCodes.SERVER_SENDING_MESSAGE
            if message[2] == 1:  # Message type 1: only text
                msg = str(converID) + Constants.SEPERATOR + str(message[0]) + Constants.SEPERATOR + str(message[1]) + Constants.SEPERATOR + str(
                    message[2]) + Constants.SEPERATOR + str(
                    message[3]) + Constants.SEPERATOR + Constants.SEPERATOR + str(message[5])
            else:
                msg = bytes(message[0]) + Constants.SEPERATOR.encode() + bytes(
                    message[1]) + Constants.SEPERATOR.encode() + bytes(message[
                                                                           2]) + Constants.SEPERATOR.encode() + message[
                          3].encode() + Constants.SEPERATOR.encode() + message[4] + Constants.SEPERATOR.encode() + \
                      bytes(message[5])
            snd = threading.Thread(target=self.send_to_client, args=(header, msg, client.conn, client))
            snd.start()
        except Exception as error:
            print(error)

    def send_to_client(self, header, msg, conn, client):
        if client.encrypted_comms is True:
            while client.socket_in_use: # In order to not send a lot of packets simultaneously and break the socket.
                time.sleep(0.01)
            client.socket_in_use = True
            header = str(header).zfill(Constants.HEADER_LENGTH).encode()
            if type(msg) is not bytes:
                msg = msg.encode()
            print("sending:".encode() + header + msg)
            encrypted_data, nonce = client.aes.encrypt_data(header + msg)
            packet_len = str(len(encrypted_data)).zfill(10).encode()
            print("actual data len: ", packet_len)
            packet = encrypted_data
            conn.send(str(len(nonce)).zfill(2).encode() + nonce + packet_len)
            packet_sent_len = 0
            packet_len = int(packet_len)
            while packet_sent_len < packet_len:
                conn.send(packet[packet_sent_len:packet_sent_len + 1024])
                packet_sent_len += len(packet[packet_sent_len:packet_sent_len + 1024])
                print("sent until now: ", packet_sent_len)
            client.socket_in_use = False
            print("done sending")
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
        if blacklist in password or not len(password) <= 1024: # TODO: Lower char count
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
        self.userdb = None
        self.userdata = {"nickname": None, "email": None, "phonenum": None, "username": None}
        self.socket_in_use = False

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

    def userdb(self):
        if self.userId is not None:
            return self.userdb
        return None

    def set_user_using_ID(self, ID):
        self.userId = ID
        self.userdb = userdb.User(self.userId)
        db_userdata = self.db.select_userdata_by_userId(ID, "all")
        self.userdata["nickname"] = db_userdata[1]
        self.userdata["email"] = db_userdata[2]
        self.userdata["phonenum"] = db_userdata[3]
        self.userdata["username"] = db_userdata[4]
        print(self.userdb.get_all_convers())


class ResponseCodes(IntEnum):
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
    UPDATE_CONVERSATION_DATA_HEADER_CODE = 220
    UPDATE_CONVERSATION_DATA_SUCCESS_HEADER_CODE = 221
    UPDATE_CONVERSATION_DATA_FAIL_HEADER_CODE = 222
    LEAVE_CONVERSATION_HEADER_CODE = 230
    LEAVE_CONVERSATION_SUCCESS_HEADER_CODE = 231
    REMOVE_PARTICIPANT_HEADER_CODE = 240
    REMOVE_PARTICIPANT_SUCCESS_HEADER_CODE = 241
    REMOVE_PARTICIPANT_FAILED_HEADER_CODE = 242
    GET_PARTICIPANTS_HEADER_CODE = 250
    GET_PARTICIPANT_HEADER_CODE = 2501
    GET_PARTICIPANT_SUCCESS_HEADER_CODE = 251


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


# TODO: Create response codes for sending messages, and asking to receive queued messeges.
# TODO: Display messages for successful registration and login.
# TODO: Change the packet sending protocol in order of it to actually work as intended.

server = Server("127.0.0.1", Constants.PORT)
server.startServer()
