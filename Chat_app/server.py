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
        self.db = sqlite3.connect(self.config.db_path)
        self.cursor = self.db.cursor()
        self.keys = self.get_keys()
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

    async def connect(self, websocket):
        if self.config.encrypt == "ECC":
            # initiate ECC-AES128 handshake
            key = await websocket.recv()
            websocket.send(self.keys[0])
            shared_key = ECC.ECC.compute_shared_secret(self.keys[1], key)


        elif self.config.encrypt == "RSA":
            # initiate RSA handshake
            pass














if __name__ == "__main__":
    with open("server_config.json", "r", encoding='utf-8') as fil:
        data = fil.read()
        config = Config(json.loads(data))
    server = Server(config)
    server.run()

    