import sqlite3
import os

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

        self.DBNAME = os.path.realpath("db/conversations/" + "conversationIDs.db")

        conn = sqlite3.connect(self.DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + self.__tablename + "(" + self.__conversationID + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__conversationname + " TEXT    NOT NULL ,"
        query_str += " " + self.__conversationtype + " INTEGER    NOT NULL );"

        conn.execute(query_str)
        conn.commit()
        conn.close()

    def create_new_conversation(self, name, contype=1):
        conn = sqlite3.connect(self.DBNAME)
        print(name)
        if contype == 1 and not self.check_if_conversation_exists(name):
            insert_query = (
                    "INSERT INTO " + self.__tablename + " (" + self.__conversationname + "," + self.__conversationtype + ") " + "VALUES "
                    + "(?,?)")
            conn.execute(insert_query, (str(name), contype))
            conn.commit()
            conn.close()

            print("successfuly created conversation: " + name)
            return self.get_conversationID_by_name(name), name # TODO URGENT: Change to last_rowid

        elif contype == 1 and self.check_if_conversation_exists(name):
            conn.close()
            print("conversation: " + name + "already exists")
            return None, None

        conn.close()

    def get_conversationID_by_name(self, name):
        # FIXME: Find and fix this weird ass bug which causes this def to always return "1"
        conn = sqlite3.connect(self.DBNAME)
        print(name)
        query = "SELECT " + self.__conversationID + " FROM " + self.__tablename + " WHERE " + self.__conversationname + " = " + "'" + name + "'"
        cursor = conn.execute(query)
        conversationid = cursor.fetchone()[0]
        conn.close()
        return conversationid

    def check_if_conversation_exists(self, name):
        conn = sqlite3.connect(self.DBNAME)
        query = "SELECT 1 from " + self.__tablename + " WHERE " + self.__conversationname + " = " + "'" + name + "'"
        cursor = conn.execute(query)
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True
