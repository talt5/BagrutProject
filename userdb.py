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
        self.__CONVERSATION = "conversation"
        self.__IS_ADMIN = "is_admin"

        self.userID = userID
        self.DBNAME = os.path.realpath("db/users/" + str(userID) + ".db")

        conn = sqlite3.connect(self.DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + self.__CONVERSATION_PARTICIPANT_TABLE + "(" + "row" + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__CONVERSATION + " INTEGER NOT NULL);"
        conn.execute(query_str)
        conn.commit()
        conn.close()

    def add_conversation(self, conversationID: int):
        conn = sqlite3.connect(self.DBNAME)
        print(conversationID)
        # TODO: Check if sender is part of the conversation.
        insert_query = (
                    "INSERT INTO " + self.__CONVERSATION_PARTICIPANT_TABLE + " (" + self.__CONVERSATION + ") VALUES (?)")
        conn.execute(insert_query, str(conversationID))
        conn.commit()
        conn.close()
        print("Conversation added successfully")
