import sqlite3
import os


class User:
    """Creates database with users table includes:
       create query
       insert query
       select query
    """
    """Message order is: 

    """

    def __init__(self, userID):
        self.__CONVERSATION_PARTICIPANT_TABLE = "converprtctable"
        self.__CONVERSATIONID = "conversationID"

        self.userID = userID
        self.DBNAME = os.path.realpath("db/users/" + str(userID) + ".db")

        conn = sqlite3.connect(self.DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + self.__CONVERSATION_PARTICIPANT_TABLE + "(" + "row" + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__CONVERSATIONID + " INTEGER NOT NULL);"
        conn.execute(query_str)
        conn.commit()
        conn.close()

    def add_conversation(self, conversationID: int):
        conn = sqlite3.connect(self.DBNAME)
        print(conversationID)
        # TODO: Check if sender is part of the conversation.
        insert_query = (
                    "INSERT INTO " + self.__CONVERSATION_PARTICIPANT_TABLE + " (" + self.__CONVERSATIONID + ") VALUES (?)")
        print(conversationID)
        conn.execute(insert_query, (str(conversationID),))
        conn.commit()
        conn.close()
        print("Conversation added successfully")

    def check_if_part_of_conversation(self, conversationID: int):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT 1 from " + self.__CONVERSATION_PARTICIPANT_TABLE + " WHERE " + self.__CONVERSATIONID + " = " + "'" + str(conversationID) + "'"
        cursor = conn.execute(query)
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True

    def get_all_convers(self):
        conn = sqlite3.connect(self.DBNAME)
        query = query = "SELECT " + self.__CONVERSATIONID + " FROM " + self.__CONVERSATION_PARTICIPANT_TABLE
        cursor = conn.execute(query)
        return cursor.fetchall()