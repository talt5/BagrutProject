import sqlite3
import os
import userdb as userdb
import messagedb as meesagedb


class Conversations:
    """Creates database with users table includes:
       create query
       insert query
       select query
    """

    def __init__(self):
        self.__tablename = "conversations"
        self.__conversationID = "conversationID"
        self.__conversationname = "conversationname"
        self.__conversationtype = "conversationtype"
        self.__conversationimage = "conversationimage"

        self.DBNAME = os.path.realpath("db/conversations/" + "conversationIDs.db")

        conn = sqlite3.connect(self.DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + self.__tablename + "(" + self.__conversationID + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__conversationname + " TEXT    NOT NULL ,"
        query_str += " " + self.__conversationtype + " INTEGER    NOT NULL ,"
        query_str += " " + self.__conversationimage + " TEXT );"

        conn.execute(query_str)
        conn.commit()
        conn.close()

    def create_new_conversation(self, creatorID, secUserID, name, image=None, contype=1):
        conn = sqlite3.connect(self.DBNAME)
        print(name)
        if contype == 1 and not self.get_private_conversation_with_both_users(creatorID,
                                                                              secUserID):
            insert_query = (
                    "INSERT INTO " + self.__tablename + " (" + self.__conversationname + "," + self.__conversationtype + "," + self.__conversationimage + ") " + "VALUES "
                    + "(?,?,?)")
            cursor = conn.cursor()
            cursor.execute(insert_query, (str(name), contype, image))
            conn.commit()
            converID = cursor.lastrowid
            conn.close()

            print("successfuly created private conversation: " + name)
            return converID, name

        elif contype == 1 and self.get_private_conversation_with_both_users(creatorID, secUserID):
            conn.close()
            print("conversation: " + name + "already exists")
            return None, None

        elif contype == 2:
            insert_query = (
                    "INSERT INTO " + self.__tablename + " (" + self.__conversationname + "," + self.__conversationtype + "," + self.__conversationimage + ") " + "VALUES "
                    + "(?,?,?)")
            cursor = conn.cursor()
            cursor.execute(insert_query, (str(name), contype, image))
            conn.commit()
            converID = cursor.lastrowid
            conver_image = self.get_conver_spdata_by_id(converID=converID, spdata=self.__conversationimage)
            conn.close()
            print("successfuly created group conversation: " + name)

            return converID, name, conver_image

        conn.close()

    def get_private_conversation_with_both_users(self, userID, sec_userID):
        conn = sqlite3.connect(self.DBNAME)
        userdata = userdb.User(userID=userID)
        userconvers = userdata.get_all_convers()
        for converID in userconvers:
            converID = converID[0]
            print("converid: ", converID)
            mdb = meesagedb.Conversation(conversationID=converID)
            query = "SELECT " + self.__conversationtype + " FROM " + self.__tablename + " WHERE " + self.__conversationID + " = (?)"
            cursor = conn.cursor()
            cursor.execute(query, (converID,))
            conver_type = cursor.fetchone()[0]
            print("convertype: ", conver_type)
            if conver_type == 1 and mdb.check_if_user_is_participating(sec_userID):
                conn.close()
                print("sec_user conver exists")
                return converID
        conn.close()
        print("sec_user conver not exists")
        return 0

    def check_if_conversation_exists(self, name):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT 1 from " + self.__tablename + " WHERE " + self.__conversationname + " = (?)"
        cursor = conn.execute(query, (name,))
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True

    def get_conver_spdata_by_id(self, converID, spdata):
        conn = sqlite3.connect(self.DBNAME)
        if any(field == spdata for field in (self.__conversationID, self.__conversationname, self.__conversationtype, self.__conversationimage)):
            query = "SELECT " + spdata + " from " + self.__tablename + " WHERE " + self.__conversationID + " = (?)"
            cursor = conn.execute(query, (converID,))
            conver_spdata = cursor.fetchone()[0]
            conn.close()
            return conver_spdata
        conn.close()

    def change_conver_info(self, converID, info, spdata):
        conn = sqlite3.connect(self.DBNAME)
        if any(field == spdata for field in
               (self.__conversationID, self.__conversationname, self.__conversationtype, self.__conversationimage)):
            query = "UPDATE " + self.__tablename + " SET " + spdata + "='" + str(info) + "' WHERE " + self.__conversationID + " = (?)"
            conn.execute(query, (converID,))
            conn.commit()
        conn.close()

    def remove_conversation(self, converID):
        conn = sqlite3.connect(self.DBNAME)
        query = "DELETE FROM " + self.__tablename + " WHERE " + self.__conversationID + " = (?)"
        conn.execute(query, (converID,))
        conn.commit()
        conn.close()