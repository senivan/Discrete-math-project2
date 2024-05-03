import asyncio
import websockets
import json
from Encryption_algos import RSA
import hashlib
import datetime
class Message:
    def __init__(self, data, time_sent, sender_username, type, hash):
        self.data = data
        self.time_sent = time_sent
        self.sender_username = sender_username
        self.type = type
        self.hash = hash
class EncDecWrapper:

    @staticmethod
    def encrypt(message, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.encrypt(message, kwargs["public_key"])
    
    @staticmethod
    def decrypt(encoded, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.decrypt(encoded, kwargs["private_key"])
    
    @staticmethod
    def generate_keys(protocol):
        if protocol == "RSA":
            return RSA.generateRSAkeys()
    
    @staticmethod
    async def handshake(protocol, websocket, **kwargs):
        if protocol == "RSA":
            msg = json.dumps(kwargs["public_key"])
            await websocket.send(msg)
            server_public_key = await websocket.recv()
            server_public_key = json.loads(server_public_key)
            return server_public_key


public_key, private_key = RSA.generateRSAkeys()
async def receive_message(websocket):
    while True:
        message = await websocket.recv()
        print(f"Received: {EncDecWrapper.decrypt(message, 'RSA', private_key=private_key)}")
        await asyncio.sleep(0.1)

async def send_message(websocket):
    global server_public_key
    while True:
        message = input("Enter message: ")
        to_send = Message(message, datetime.datetime.now().strftime("%Y-%m-%d-%H-%M"), username, "txt", hashlib.sha256(message.encode('utf-8')).hexdigest())
        await websocket.send(EncDecWrapper.encrypt(json.dumps(to_send.__dict__), "RSA", public_key=server_public_key))
        await asyncio.sleep(0.1)

async def connect_to_server():
    async with websockets.connect("ws://localhost:8000") as websocket:
        await websocket.send("Initiate handshake")
        comm_protocol = await websocket.recv()
        comm_protocol = json.loads(comm_protocol)
        global server_public_key 
        server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key)
        global username
        username = input("Enter username: ")
        password = input("Enter password: ")
        password = hashlib.sha256(password.encode('utf-8'), usedforsecurity=True).hexdigest()
        msg = EncDecWrapper.encrypt(json.dumps({"username": username, "password": password}), public_key=server_public_key, protocol=comm_protocol)
        await websocket.send(msg)
        response = await websocket.recv()
        response = EncDecWrapper.decrypt(response, private_key=private_key, protocol=comm_protocol)
        print(f"Response: {response}")
        if response == "Success":
            print("Login successful")
            send_task = asyncio.create_task(send_message(websocket))
            receive_task = asyncio.create_task(receive_message(websocket))
            done, pending = await asyncio.wait([send_task, receive_task], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            
            
            
        else:
            print("Login failed")
    



if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(connect_to_server())