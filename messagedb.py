import sqlite3
import os
from datetime import datetime


class Conversation:
    """Creates database with users table includes:
       create query
       insert query
       select query
    """
    """Message order is: 
        
    """

    def __init__(self, conversationID):
        self.__msgtablename = "messages"
        self.__userId = "userId"
        self.__messageID = "messageID"
        self.__messagesender = "messagesender"
        self.__messagetype = "type"
        self.__messagetext = "text"
        self.__messagecontentblob = "contentblob"
        self.__messagetime = "time"

        self.__prtctablename = "participants"
        self.__isadmin = "isadmin"

        self.conversationID = conversationID
        self.DBNAME = os.path.realpath("db/conversations/" + str(conversationID) + ".db")

        conn = sqlite3.connect(self.DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + self.__msgtablename + "(" + self.__messageID + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__messagesender + " INTEGER    NOT NULL ,"
        query_str += " " + self.__messagetype + " INTEGER    NOT NULL ,"
        query_str += " " + self.__messagetext + " TEXT ,"
        query_str += " " + self.__messagecontentblob + " BLOB ,"
        query_str += " " + self.__messagetime + " TEXT    NOT NULL );"

        conn.execute(query_str)

        query_str = "CREATE TABLE IF NOT EXISTS " + self.__prtctablename + "(" + self.__userId + " INTEGER NOT NULL, "
        query_str += self.__isadmin + " INTEGER NOT NULL);"

        conn.execute(query_str)

        conn.commit()
        conn.close()

    def insert_message(self, sender: int, msgtype: int, text: str = None, data: bytes = None):
        time = datetime.timestamp(datetime.now())
        conn = sqlite3.connect(self.DBNAME)
        cursor = conn.cursor()
        # TODO: Check if sender is part of the conversation.
        insert_query = (
                    "INSERT INTO " + self.__msgtablename + " (" + self.__messagesender + "," + self.__messagetype + "," + self.__messagetext + ","
                    + self.__messagecontentblob + "," + self.__messagetime + ") VALUES (?, ?, ?, ?, ?)")
        cursor.execute(insert_query, (sender, msgtype, text, data, time))
        conn.commit()
        messageID = cursor.lastrowid
        conn.close()
        print("Record created successfully")
        return messageID

    def insert_participant(self, userID: int, isadmin=0):
        conn = sqlite3.connect(self.DBNAME)
        if not self.check_if_user_is_participating(userID=userID):
            insert_query = ("INSERT INTO " + self.__prtctablename + " (" + self.__userId + "," + self.__isadmin + ") VALUES (?, ?)")
            conn.execute(insert_query, (userID, isadmin))
            conn.commit()
        conn.close()

    def check_if_user_is_participating(self, userID: int):
        conn = sqlite3.connect(self.DBNAME)
        print("checking userid: " + str(userID))
        query = "SELECT 1 from " + self.__prtctablename + " WHERE " + self.__userId + " = (?)"
        cursor = conn.execute(query, (userID,))
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True

    def get_message(self, messageID: int):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT * FROM " + self.__msgtablename + " WHERE " + self.__messageID + " = (?)"
        cursor = conn.execute(query, (messageID,)).fetchone()
        conn.close()
        return cursor

    def get_all_participant_ids(self):
        conn = sqlite3.connect(self.DBNAME)
        conn.row_factory = lambda cursor, row: row[0]
        query = "SELECT " + self.__userId + " FROM " + self.__prtctablename
        cursor = conn.execute(query).fetchall()
        conn.close()
        return cursor

    def get_last_message_id(self):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT " + self.__messageID + " FROM " + self.__msgtablename + " WHERE " + self.__messageID + " = (SELECT MAX(" + self.__messageID + ") FROM " + self.__msgtablename + ");"
        cursor = conn.execute(query).fetchone()[0]
        conn.close()
        return cursor

    def delete_message(self, messageID: int):
        conn = sqlite3.connect(self.DBNAME)
        query = "DELETE FROM " + self.__msgtablename + " WHERE " + self.__messageID + " = (?)"
        conn.execute(query, (messageID,))
        conn.commit()
        conn.close()

    def check_if_user_is_admin(self, userID: int):
        conn = sqlite3.connect(self.DBNAME)
        print("checking if userid admin: " + str(userID))
        query = "SELECT " + self.__isadmin + " from " + self.__prtctablename + " WHERE " + self.__userId + " = (?)"
        cursor = conn.execute(query, (userID,)).fetchone()[0]
        conn.close()
        if cursor == 1:
            return True
        return False

    def remove_participant(self, userID: int):
        conn = sqlite3.connect(self.DBNAME)
        if userID == 0:
            query = "DELETE FROM " + self.__prtctablename
            conn.execute(query)
        else:
            query = "DELETE FROM " + self.__prtctablename + " WHERE " + self.__userId + " = (?)"
            conn.execute(query, (userID,))
        conn.commit()
        conn.close()
