import sqlite3
import os


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
        time = "123"  # TODO: Get current time
        conn = sqlite3.connect(self.DBNAME)
        # TODO: Check if sender is part of the conversation.
        insert_query = ("INSERT INTO " + self.__msgtablename + " (" + self.__messagesender + "," + self.__messagetype + "," + self.__messagetext + ","
                        + self.__messagecontentblob + "," + self.__messagetime + ") VALUES (?, ?, ?, ?, ?)")
        conn.execute(insert_query, (sender, msgtype, text, data, time))
        conn.commit()
        conn.close()
        print("Record created successfully")

    def insert_participant(self, userID: int, isadmin=0):
        conn = sqlite3.connect(self.DBNAME)
        insert_query = ("INSERT INTO " + self.__prtctablename + " (" + self.__userId + "," + self.__isadmin + ") VALUES "
                        + "(?, ?)")
        conn.execute(insert_query, (userID, isadmin))
        conn.commit()
        conn.close()

    def check_if_user_is_participating(self, userID: int):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT 1 from " + self.__prtctablename + " WHERE " + self.__userId + " = " + "'" + str(userID) + "'"
        cursor = conn.execute(query)
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True
