import mysql.connector
class Database:
    def __init__(self):
        self.db = mysql.connector.connect(
            host="localhost",
            user="root",
            password="password",
            database="kryptos_app"
        )
        self.cursor = self.db.cursor()
        self.init_db()
    
    def init_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                username varchar(20) NOT NULL,
                password varchar(260) NOT NULL
            )
                ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Chats (
                id INTEGER PRIMARY KEY AUTO_INCREMENT,
                participants varchar(300) NOT NULL,
                chat_history_path varchar(1) NOT NULL, 
                name varchar(30) NOT NULL
            )
                ''')
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS Messages (
                id INTEGER PRIMARY KEY,
                data TEXT NOT NULL,
                time_sent TEXT NOT NULL,
                sender_id INTEGER NOT NULL,
                chat_id INTEGER NOT NULL,
                FOREIGN KEY (sender_id) REFERENCES Users(id),
                FOREIGN KEY (chat_id) REFERENCES Chats(id),
                type INTEGER NOT NULL,
                hash TEXT NOT NULL
            )
                ''')
        self.db.commit()
    
    def add_user(self, username:str, password:str):
        self.cursor.execute('''
            INSERT INTO Users (username, password)
            VALUES (%s, %s)
            ''', (username, password))
        self.db.commit()
        return True
    def add_user_obj(self, user:'User'):
        self.cursor.execute('''
            INSERT INTO Users (username, password)
            VALUES (%s, %s)
            ''', (user.username, user.password))
        self.db.commit()
    def delete_user(self, username:str):
        self.cursor.execute('''
            DELETE FROM Users
            WHERE username = %s
            ''', (username,))
        self.db.commit()
    def get_user(self, username:str):
        self.cursor.execute('''
            SELECT * FROM Users
            WHERE username = %s
            ''', (username,))
        id, username, password = self.cursor.fetchone()
        return User(id, username, password)

    def add_chat(self, participants:str, chat_history_path:str, name:str):
        all_users = self.cursor.execute('''
            SELECT * FROM Users
            ''').fetchall()
        print(all_users)
        for participant in participants:
            print(participant, [user[1] for user in all_users])
            if participant not in [user[1] for user in all_users]:
                return False
        participants = ";".join(participants)
        self.cursor.execute('''
            INSERT INTO Chats (participants, chat_history_path, name)
            VALUES (%s, %s, %s)
            ''', (participants, chat_history_path, name))
        print(participants, chat_history_path, name)
        self.db.commit()
    
    def add_chat_obj(self, chat:'Chat'):
        self.cursor.execute('''
            INSERT INTO Chats (participants, chat_history_path, name)
            VALUES (%s, %s, %s)
            ''', (chat.participants, chat.chat_history_path, chat.name))
        self.db.commit()

    def delete_chat(self, chat_id:int):
        self.cursor.execute('''
            DELETE FROM Chats
            WHERE id = %s
            ''', (chat_id,))
        self.db.commit()
    def get_chat(self, chat_id:int):
        self.cursor.execute('''
            SELECT * FROM Chats
            WHERE id = %s
            ''', (chat_id,))
        id, participants, chat_history_path, name = self.cursor.fetchone()
        return Chat(id, participants, chat_history_path, name)

    def create_message(self, data:str, time_sent:str, sender_id:int, chat_id:int, type:int, hash:str):
        self.cursor.execute('''
            INSERT INTO Messages (data, time_sent, sender_id, chat_id, type, hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''', (data, time_sent, sender_id, chat_id, type, hash))
        self.db.commit()
    
    def create_message_obj(self, message:'Message'):
        self.cursor.execute('''
            INSERT INTO Messages (data, time_sent, sender_id, chat_id, type, hash)
            VALUES (%s, %s, %s, %s, %s, %s)
            ''', (message.data, message.time_sent, message.sender_id, message.chat_id, message.type, message.hash))
        self.db.commit()

    def delete_message(self, message_id:int):
        self.cursor.execute('''
            DELETE FROM Messages
            WHERE id = %s
            ''', (message_id,))
        self.db.commit()
    
    def get_messages(self, chat_id:int):
        self.cursor.execute('''
            SELECT * FROM Messages
            WHERE chat_id = %s
            ''', (chat_id,))
        res = []
        for msg in sorted(self.cursor.fetchall(), key=lambda x: x[1]):
            id, data, time_sent, sender_id, chat_id, type, hash = msg
            res.append(Message(id, data, time_sent, sender_id, chat_id, type, hash))
        return res
    
    def get_all_chat_messages(self, chat_id:int):
        self.cursor.execute('''
            SELECT * FROM Messages where chat_id = %s
            ''', (chat_id,))
        res = []
        for msg in self.cursor.fetchall():
            id, data, time_sent, sender_id, chat_id, type, hash = msg
            res.append(Message(id, data, time_sent, sender_id, chat_id, type, hash))
        return res
    
    def check_user(self, username:str, password:str):
        print(username, password)
        self.cursor.execute('''
            SELECT * FROM Users
            WHERE username = %s
            ''', (username,))
        possible_user = self.cursor.fetchone()
        if possible_user is None:
            return False
        return password == possible_user[2]
    
    def get_user_id(self, username:str):
        self.cursor.execute('''
            SELECT * FROM Users
            WHERE username = %s
            ''', (username,))
        return self.cursor.fetchone()[0]
    
    def cleanup(self):
        self.cursor.execute('''
            DELETE FROM Users
            ''')
        self.cursor.execute('''
            DELETE FROM Chats
            ''')
        self.cursor.execute('''
            DELETE FROM Messages
            ''')
        self.db.commit()
    
    def get_chats(self, username:str):
        self.cursor.execute('''
            SELECT * FROM Chats
        ''')
        res = []
        for chat in self.cursor.fetchall():
            id, participants, chat_history_path, name = chat
            if username in participants.split(";"):
                res.append(Chat(id, participants, chat_history_path, name))
        return res
    
    def get_username(self, id:int):
        self.cursor.execute('''
            SELECT * FROM Users
            WHERE id = %s
            ''', (id,))
        return self.cursor.fetchone()[1]

    def get_chat_participants(self, chat_id:int):
        self.cursor.execute('''
            SELECT * FROM Chats
            WHERE id = %s
            ''', (chat_id,))
        return self.cursor.fetchone()[1].split(";")

class User:
    def __init__(self,id:int, username:str, password:str):
        self.id = id
        self.username = username
        self.password = password
    def __str__(self):
        return f"User: {self.username}, Password: {self.password}"
    def __repr__(self):
        return self.__str__()

class Chat:
    def __init__(self, id,  participants:list, chat_history_path:str, name:str):
        self.chat_history_path = chat_history_path
        self.id = id
        self.name = name
        self.participants = ""
        for participant in participants:
            self.participants += f"{participant};"
    def __str__(self):
        return f"Participants: {self.participants}, Chat history path: {self.chat_history_path}"
    def __repr__(self):
        return self.__str__()
    
    def add_participant(self, participant:str):
        self.participants += f"{participant};"
    def remove_participant(self, participant:str):
        self.participants = self.participants.replace(f"{participant};", "")
    
    def get_participants(self):
        return self.participants.split(";")
    
    def change_name(self, name:str):
        self.name = name
    
    def update_self(self, db:'Database'):
        db.cursor.execute('''
            UPDATE Chats
            SET participants = ?, chat_history_path = ?, name = ?
            WHERE id = ?
            ''', (self.participants, self.chat_history_path, self.name, self.id))
        db.db.commit()
    
class Message:
    def __init__(self,id:int, data:str, time_sent:str, sender_id:int, chat_id:int, type:int, hash:str):
        self.data = data
        self.id = id
        self.time_sent = time_sent
        self.sender_id = sender_id
        self.chat_id = chat_id
        self.type = type
        self.hash = hash
    def __str__(self):
        return f"Data: {self.data}, Time sent: {self.time_sent}, Sender id: {self.sender_id}, Chat id: {self.chat_id}, Type: {self.type}, Hash: {self.hash}"
    def __repr__(self):
        return self.__str__()