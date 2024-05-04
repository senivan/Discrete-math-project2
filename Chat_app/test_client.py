import asyncio
import websockets
import json
from Encryption_algos import RSA, ECC
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
        if protocol == "ECC":
            return ECC.AES128.encrypt(kwargs["public_key"][:16], message.encode('utf-8'))
    
    @staticmethod
    def decrypt(encoded, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.decrypt(encoded, kwargs["private_key"])
        if protocol == "ECC":
            return ECC.AES128.decrypt(kwargs["public_key"][:16], encoded)
    
    @staticmethod
    def generate_keys(protocol):
        if protocol == "RSA":
            return RSA.generateRSAkeys()
        if protocol == "ECC":
            return ECC.ECC.generate_keys()
    
    @staticmethod
    async def handshake(protocol, websocket, **kwargs):
        if protocol == "RSA":
            msg = json.dumps(kwargs["public_key"])
            await websocket.send(msg)
            server_ = await websocket.recv()
            server_ = json.loads(server_)
            return server_
        if protocol == "ECC":
            msg = json.dumps(kwargs["public_key"], cls=ECC.PointEncoder)
            await websocket.send(msg)
            server_ = await websocket.recv()
            server_ = json.loads(server_)
            print(f"Server public key: {server_}")
            print(f"Client private key: {kwargs['private_key']}")
            server_ = ECC.Point(server_["x"], server_["y"])
            priv = kwargs["private_key"]
            print(type(priv), type(server_))
            shared_secret = ECC.ECC.derive_key_function(priv, server_)
            print(f"Shared secret: {shared_secret}")
            return shared_secret



async def receive_message(websocket):

    while True:
        message = await websocket.recv()
        if comm_protocol == "RSA":
            message = EncDecWrapper.decrypt(message, comm_protocol, private_key=private_key)
        if comm_protocol == "ECC":
            message = EncDecWrapper.decrypt(message, comm_protocol, public_key=server_public_key)
        message = json.loads(message)
        print(f"Received: {message['data']} from {message['sender_username']} at {message['time_sent']}")
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
        global public_key, private_key, comm_protocol
        comm_protocol = await websocket.recv()
        comm_protocol = json.loads(comm_protocol)
        if comm_protocol == "RSA":
            public_key, private_key = EncDecWrapper.generate_keys("RSA")
        if comm_protocol == "ECC":
            private_key, public_key = EncDecWrapper.generate_keys("ECC")
        global server_public_key 
        server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key, private_key=private_key)
        print(f"Server public key: {server_public_key}")
        global username
        username = input("Enter username: ")
        password = input("Enter password: ")
        password = hashlib.sha256(password.encode('utf-8'), usedforsecurity=True).hexdigest()
        msg = EncDecWrapper.encrypt(json.dumps({"username": username, "password": password}), public_key=server_public_key, protocol=comm_protocol)
        await websocket.send(msg)
        response = await websocket.recv()
        response = EncDecWrapper.decrypt(response, private_key=private_key, protocol=comm_protocol, public_key=server_public_key)
        print(f"Response: {response}")
        response = response.decode().strip('\x00')
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