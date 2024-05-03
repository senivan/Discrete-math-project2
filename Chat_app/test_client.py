import asyncio
import websockets
import json
from Encryption_algos import RSA
import hashlib


public_key, private_key = RSA.generateRSAkeys()
async def connect_to_server():
    async with websockets.connect("ws://localhost:8000") as websocket:
        msg = json.dumps(public_key)
        await websocket.send(msg)
        server_public_key = await websocket.recv()
        server_public_key = json.loads(server_public_key)
        # print(f"Server public key: {server_public_key}")
        # while True:
        #     message = input("Enter message: ")
        #     await websocket.send(RSA.encrypt(message, server_public_key))
        #     print(f"Server: {await websocket.recv()}")
        username = input("Enter username: ")
        password = input("Enter password: ")
        password = hashlib.sha256(password.encode('utf-8'), usedforsecurity=True).hexdigest()
        msg = RSA.encrypt(json.dumps({"username": username, "password": password}), server_public_key)
        await websocket.send(msg)
        response = await websocket.recv()
        print(f"Response: {RSA.decrypt(response, private_key)}")



if __name__ == "__main__":
    asyncio.get_event_loop().run_until_complete(connect_to_server())