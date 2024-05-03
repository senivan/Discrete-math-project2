import asyncio
import websockets
import json
from Encryption_algos import RSA
import hashlib

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
async def connect_to_server():
    async with websockets.connect("ws://localhost:8000") as websocket:
        await websocket.send("Initiate handshake")
        comm_protocol = await websocket.recv()
        comm_protocol = json.loads(comm_protocol)
        server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key)
        username = input("Enter username: ")
        password = input("Enter password: ")
        password = hashlib.sha256(password.encode('utf-8'), usedforsecurity=True).hexdigest()
        msg = EncDecWrapper.encrypt(json.dumps({"username": username, "password": password}), public_key=server_public_key, protocol=comm_protocol)
        await websocket.send(msg)
        response = await websocket.recv()
        print(f"Response: {EncDecWrapper.decrypt(response, private_key=private_key, protocol=comm_protocol)}")



if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(connect_to_server())