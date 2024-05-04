"""
    This is the server side of the chat applications
    It should be pretty simple WebSocket server with SqlLite database
    to store the messages and user information.
    The server should be able to handle multiple clients at the same time
    and should be able to send and receive messages from the clients.
"""
import asyncio
import websockets
import hashlib
import json
import os
from Encryption_algos import ECC, RSA
from server_utils import database

class Keys:
    @staticmethod
    def get_public_key(protocol):
        secret = json.loads(open("server_util/server_secret.json", "r").read())
        if protocol not in secret.keys():
            if protocol == "RSA":
                pub, priv = RSA.generateRSAkeys()
            if protocol == "ECC":
                pub, priv = ECC.ECC.generate_keys()
            secret[protocol]["public_key"] = pub
            secret[protocol]["private_key"] = priv
            with open("server_util/server_secret.json", "w") as file:
                file.write(json.dumps(secret))
            return pub
        else:
            return secret[protocol]["public_key"]
    @staticmethod
    def get_private_key(protocol):
        secret = json.loads(open("server_util/server_secret.json", "r").read())
        if protocol not in secret.keys():
            if protocol == "RSA":
                pub, priv = RSA.generateRSAkeys()
            if protocol == "ECC":
                pub, priv = ECC.ECC.generate_keys()
            secret[protocol]["public_key"] = pub
            secret[protocol]["private_key"] = priv
            with open("server_util/server_secret.json", "w") as file:
                file.write(json.dumps(secret))
            return priv
        else:
            return secret[protocol]["private_key"]

class Config:
    def __init__(self, conf):
        self.encrypt = conf["encrypt"]
        self.db_path = conf["db_path"]
        self.host = conf["host"]
        self.port = conf["port"]

class Server:
    def __init__(self, config:'Config'):
        self.config = config
        self.db = database.Database(self.config.db_path)
        self.users = {}
        self.keys = (Keys.get_public_key(self.config.encrypt), Keys.get_private_key(self.config.encrypt))

    def run(self):
        start_server = websockets.serve(self.connect, self.config.host, self.config.port, ping_interval=30, ping_timeout=120)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()
    
    async def send_message(self, message):
        message = json.dumps(message)
        for user in self.users:
            await user.send(RSA.encrypt(message, self.users[user][1]))
    
    async def handle_client(self, websocket):
        while True:
            try:
                message = await websocket.recv()
                message = RSA.decrypt(message, self.keys[1])
                message = json.loads(message)
                if hashlib.sha256(message['data'].encode('utf-8')).hexdigest() != message['hash']:
                    print("Message has been tampered with")
                    continue
                self.db.create_message(message["data"], message["time_sent"], self.db.get_user_id(message["sender_username"]),0, message["type"], message["hash"])
                # message = json.loads(message)
                print(f"Received: {message['data']}")
                await self.send_message(message)
            except websockets.exceptions.ConnectionClosedError:
                print("Client disconnected")
                break

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
                self.users[websocket] = (login_info["username"], client_key)
                await self.handle_client(websocket)
            else:
                await websocket.send(RSA.encrypt("Failed", client_key))














if __name__ == "__main__":
    with open("server_config.json", "r", encoding='utf-8') as fil:
        data = fil.read()
        config = Config(json.loads(data))
    server = Server(config)
    # server.db.add_user("test1", hashlib.sha256("test1".encode('utf-8')).hexdigest())
    server.run()

    