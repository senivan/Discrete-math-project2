import sqlite3

class Database:
    def __init__(self, db_path:str):
        self.db = sqlite3.connect(db_path)
        self.cursor = self.db.cursor()
        self.create_table()
    
    def create_table(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT
        )''')
        self.db.commit()
    
    def add_user(self, username:str, password:str):
        self.cursor.execute('''INSERT INTO users (username, password) VALUES (?, ?)''', (username, password))
        self.db.commit()
    
    def get_user(self, username:str):
        self.cursor.execute('''SELECT * FROM users WHERE username = ?''', (username,))
        user = self.cursor.fetchone()
        return user
    
    def get_all_users(self):
        self.cursor.execute('''SELECT * FROM users''')
        users = self.cursor.fetchall()
        return users
    
    def delete_user(self, username:str):
        self.cursor.execute('''DELETE FROM users WHERE username = ?''', (username,))
        self.db.commit()
    
    def update_password(self, username:str, password:str):
        self.cursor.execute('''UPDATE users SET password = ? WHERE username = ?''', (password, username))
        self.db.commit()
    
    def __del__(self):
        self.db.close()