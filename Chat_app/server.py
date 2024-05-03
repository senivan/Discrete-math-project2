"""
    This is the server side of the chat applications
    It should be pretty simple WebSocket server with SqlLite database
    to store the messages and user information.
    The server should be able to handle multiple clients at the same time
    and should be able to send and receive messages from the clients.
"""
import asyncio
import websockets
import sqlite3
import json
import os
from Encryption_algos import ECC, RSA
from server_utils import database

class Keys:
    def __init__(self, public_key, private_key):
        self.public_key = public_key
        self.private_key = private_key
    
    def get_public_key(self):
        return self.public_key
    
    def get_private_key(self):
        return self.private_key
    @staticmethod
    def from_tuple(tup):
        return Keys(tup[0], tup[1])
    
    def __str__(self):
        return f"Public key: {self.public_key}\nPrivate key: {self.private_key}"
    
    def __getitem__(self, key):
        if key == 0:
            return self.public_key
        elif key == 1:
            return self.private_key
        else:
            raise IndexError("Index out of range")
class Config:
    def __init__(self, conf):
        self.encrypt = conf["encrypt"]
        self.db_path = conf["db_path"]
        self.host = conf["host"]
        self.port = conf["port"]
        self.public_key_path = conf["public_key_path"]
        self.private_key_path = conf["private_key_path"]

class Server:
    def __init__(self, config:'Config'):
        self.config = config
        self.db = database.Database(self.config.db_path)
        self.keys = Keys.from_tuple(self.get_keys())
        print(f"Keys: {self.keys}")
        self.users = {}
    
    def get_keys(self):
        if os.path.exists(self.config.public_key_path) and os.path.exists(self.config.private_key_path):
            with open(self.config.public_key_path, "r", encoding='utf-8') as file:
                public_key = json.loads(file.read())
            with open(self.config.private_key_path, "r", encoding='utf-8') as file:
                private_key = json.loads(file.read())
            return (public_key, private_key)
        else:
            if self.config.encrypt == "ECC":
                keys = ECC.ECC.generate_keys()
            elif self.config.encrypt == "RSA":
                keys = RSA.generateRSAkeys()
            with open(self.config.public_key_path, "w") as file:
                file.write(json.dumps(keys[0]))
            with open(self.config.private_key_path, "w") as file:
                if self.config.encrypt == "ECC":
                    file.write(json.dumps(keys[1], cls=ECC.PointEncoder))
                else:
                    file.write(json.dumps(keys[1]))
            return keys
        

    def run(self):
        start_server = websockets.serve(self.connect, self.config.host, self.config.port)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()
    
    async def send_message(self, message):
        for user in self.users:
            await user.send(message)

    async def connect(self, websocket):
        print("Connected to client")
        await websocket.recv()
        msg = json.dumps(self.config.encrypt)
        print(f"Sending: {msg}")
        await websocket.send(msg)
        if self.config.encrypt == "ECC":
            # initiate ECC-AES128 handshake
            key = await websocket.recv()
            
            websocket.send(self.keys[0])
            shared_key = ECC.ECC.compute_shared_secret(self.keys[1], key)


        elif self.config.encrypt == "RSA":
            # initiate RSA handshake
            client_key = await websocket.recv()
            client_key = json.loads(client_key)
            print(f"Client key: {client_key}")
            await websocket.send(json.dumps(self.keys[0]))
            login_info = await websocket.recv()
            login_info = RSA.decrypt(login_info, self.keys[1])
            login_info = json.loads(login_info)
            print(f"Login info: {login_info}")
            if self.db.check_user(login_info["username"], login_info["password"]):
                await websocket.send(RSA.encrypt("Success", client_key))

            else:
                await websocket.send(RSA.encrypt("Failed", client_key))















if __name__ == "__main__":
    with open("server_config.json", "r", encoding='utf-8') as fil:
        data = fil.read()
        config = Config(json.loads(data))
    server = Server(config)
    server.run()

    