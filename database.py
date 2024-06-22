import sqlite3
import os

DBNAME = os.path.realpath("db/users/" + "test.db")


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
        profilepic
    """
    # TODO: Make a single select_userdata_by_something.
    def __init__(self, tablename="users", userId="userId", fullname="fullname", email="email", password="password",
                 username="username", phonenum="phonenum", profilepic="profilepic"):
        self.__tablename = tablename
        self.__userId = userId
        self.__fullname = fullname
        self.__email = email
        self.__username = username
        self.__password = password
        self.__phonenum = phonenum
        self.__profilepic = profilepic

        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        query_str = "CREATE TABLE IF NOT EXISTS " + tablename + "(" + self.__userId + " " + \
                    " INTEGER PRIMARY KEY AUTOINCREMENT ,"
        query_str += " " + self.__fullname + " TEXT    NOT NULL ,"
        query_str += " " + self.__email + " TEXT    NOT NULL ,"
        query_str += " " + self.__phonenum + " TEXT    NOT NULL ,"
        query_str += " " + self.__username + " TEXT    NOT NULL ,"
        query_str += " " + self.__password + " TEXT    NOT NULL ,"
        query_str += " " + self.__profilepic + " TEXT    NOT NULL );"

        conn.execute(query_str)
        conn.commit()
        conn.close()

    def insert_user(self, fullname, email, phonenum, username, password, profilepic):
        conn = sqlite3.connect(DBNAME)
        insert_query = "INSERT INTO " + self.__tablename + " (" + self.__fullname + "," + self.__email + "," + self.__phonenum + "," + self.__username + "," + self.__password + "," + self.__profilepic +") VALUES " + "(?,?,?,?,?,?);"
        conn.execute(insert_query, (fullname, email, phonenum, username, password, profilepic))
        conn.commit()
        conn.close()
        print("Record created successfully")

    def select_userdata_by_username(self, username, spdata):
        conn = sqlite3.connect(DBNAME)
        print(spdata)
        print("Opened database successfully")
        if spdata == "all" or spdata is None:
            operation = "SELECT userId, fullname, email, phonenum, username, password, profilepic  from " + self.__tablename + " where " + self.__username + "=" \
                        + "'" + str(username) + "'"
        elif any(field == spdata for field in ("userId", "fullname", "email", "phonenum", "username", "password", "profilepic")):
            operation = "SELECT " + spdata + " from " + self.__tablename + " where " + self.__username + "=" + "'" + str(
                username) + "'"
        else:
            return None

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

    def select_userdata_by_userId(self, userId, spdata):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        if spdata == "all":
            operation = "SELECT userId, fullname, email, phonenum, username, password, profilepic  from " + self.__tablename + " where " + self.__userId + "= (?)"
        elif any(field == spdata for field in ("userId", "fullname", "email", "phonenum", "username", "password", "profilepic")):
            operation = "SELECT " + spdata + " from " + self.__tablename + " where " + self.__userId + "= (?)"
        else:
            return None

        cursor = conn.execute(operation, (userId,))
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
        operation = "SELECT 1 from " + self.__tablename + " WHERE " + self.__username + " = (?)"
        cursor = conn.execute(operation, (username,))
        if cursor.fetchone() is None:
            conn.close()
            return False
        else:
            conn.close()
            return True

    def delete_user(self, userId):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        str1 = "DELETE FROM " + self.__tablename + " WHERE " + self.__userId + " = (?)"

        conn.execute(str1, (userId,))
        conn.commit()
        print("Operation done successfully")
        conn.close()

    def update_password(self, userId, password):
        conn = sqlite3.connect(DBNAME)
        print("Opened database successfully")
        str1 = "UPDATE " + self.__tablename + " SET " + self.__password + " = :password" " WHERE " + self.__userId + " = :userID"

        conn.execute(str1, {"password": password, "userID": userId})
        conn.commit()
        print("Operation done successfully")
        conn.close()
