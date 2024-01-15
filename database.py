##############################################################
#Tal Trakhtenberg
#Mesima register login
#03.01.2024
#Database
##############################################################
import sqlite3

DBNAME = "test.db"


class Users:
    """Creates database with users table includes:
       create query
       insert query
       select query
    """
    """User info order is: 
        userId
        fullname
        email
        phonenum
        username
        password
    """

    def __init__(self, tablename="users", userId="userId", fullname="fullname", email="email", password="password",
                 username="username", phonenum="phonenum"):
        self.__tablename = tablename
        self.__userId = userId
        self.__fullname = fullname
        self.__email = email
        self.__username = username
        self.__password = password
        self.__phonenum = phonenum

        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + tablename + "(" + self.__userId + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__fullname + " TEXT    NOT NULL ,"
        query_str += " " + self.__email + " TEXT    NOT NULL ,"
        query_str += " " + self.__phonenum + " TEXT    NOT NULL ,"
        query_str += " " + self.__username + " TEXT    NOT NULL ,"
        query_str += " " + self.__password + " TEXT    NOT NULL );"


        conn.execute(query_str)
        conn.commit()
        conn.close()

    def __str__(self):
        return "table  name is ", self.__tablename

    def get_table_name(self):
        return self.__tablename

    def insert_user(self, fullname, email, phonenum, username, password):
        conn = sqlite3.connect(DBNAME)
        insert_query = "INSERT INTO " + self.__tablename + " (" + self.__fullname + "," + self.__email + "," + self.__phonenum + "," + self.__username + "," + self.__password + ") VALUES " \
                                                                                                                                                                                 "(" + "'" + fullname + "'" + "," + "'" + email + "'" + "," + "'" + phonenum + "'" + "," + "'" + username + "'" + "," + "'" + password + "'" + ");"
        conn.execute(insert_query)
        conn.commit()
        conn.close()
        print("Record created successfully")

    def select_userdata_by_id(self, userId):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        operation = "SELECT userId, fullname, email, phonenum, username, password  from " + self.__tablename + " where " + self.__userId + "=" \
                    + str(userId)

        cursor = conn.execute(operation)
        for row in cursor:
            print("userId = ", row[0])
            print("fullname = ", row[1])
            print("email = ", row[2])
            print("phonenum = ", row[3])
            print("username = ", row[4])
            print("password = ", row[5])

        print("Operation done successfully")
        conn.close()

    def select_userdata_by_username(self, username, spdata):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        if spdata is None:
            operation = "SELECT userId, fullname, email, phonenum, username, password  from " + self.__tablename + " where " + self.__username + "=" \
                        + "'" + str(username) + "'"
        elif spdata is not None:
            operation = "SELECT " + spdata + " from " + self.__tablename + " where " + self.__username + "=" + "'" + str(
                username) + "'"

        cursor = conn.execute(operation)
        userdata = []
        for row in cursor:
            if len(row) > 1:
                for item in row:
                    userdata.append(item)
            elif len(row) == 1:
                userdata = row[0]

        print("Operation done successfully")
        conn.close()
        return userdata

    def check_if_username_exists(self, username):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        operation = "SELECT 1 from " + self.__tablename + " WHERE " + self.__username + " = " + "'" + username + "'"
        cursor = conn.execute(operation)
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True

    def select_all(self):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        str1 = "SELECT * from " + self.__tablename
        cursor = conn.execute(str1)
        for row in cursor:
            print("userId = ", row[0])
            print("fullname = ", row[1])
            print("email = ", row[2])

        conn.close()

    def delete_user(self, userId):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        str1 = "DELETE FROM " + self.__tablename + " WHERE " + self.__userId + " = " \
               + str(userId)

        conn.execute(str1)
        conn.commit()
        print("Operation done successfully")
        conn.close()

    def update_password(self, userId, password):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        str1 = "UPDATE " + self.__tablename + " SET " + self.__password + " = " \
               + "'" + password + "'" + " WHERE " + self.__userId + " = " + str(userId)

        conn.execute(str1)
        conn.commit()
        print("Operation done successfully")
        conn.close()
