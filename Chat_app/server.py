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
from Encryption_algos import ECC, RSA, ElGamal
from server_utils import database, logger

_logger = logger.Logger("./server_utils/server.log")
class EncDecWrapper:
    @staticmethod
    def encrypt(message, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.encrypt(message, kwargs["public_key"])
        if protocol == "ECC":
            return ECC.AES128.encrypt(kwargs["shared_key"], message.encode('utf-8'))
        if protocol == "ElGamal":
            pub = kwargs["public_key"]
            if isinstance(pub, dict):
                pub = pub.values()
            return json.dumps(ElGamal.encrypt(pub, message))
    @staticmethod
    def decrypt(encoded, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.decrypt(encoded, kwargs["private_key"])
        if protocol == "ECC":
            res = ECC.AES128.decrypt(kwargs["shared_key"], encoded)
            return res.decode('utf-8').strip('\x00')
        if protocol == "ElGamal":
            c1, c2 = json.loads(encoded)
            return ElGamal.decrypt(kwargs["private_key"], c1, c2)
    
    @staticmethod
    async def handshake(protocol, websocket, **kwargs):
        _logger.log(f"Handshake started for {protocol}", 1)
        await websocket.recv()
        msg = json.dumps(protocol)
        _logger.log(f"Sending: {msg}", 1)
        await websocket.send(msg)
        if protocol == "RSA":
            client_key = await websocket.recv()
            client_key = json.loads(client_key)
            _logger.log(f"Client key: {client_key}", 1)
            await websocket.send(json.dumps(kwargs["public_key"]))
            return client_key
        if protocol == "ECC":
            client_key = await websocket.recv()
            client_key = json.loads(client_key)
            client_key = ECC.Point(client_key["x"], client_key["y"])
            _logger.log(f"Client key: {client_key}", 1)
            await websocket.send(json.dumps(kwargs["public_key"]))
            shared_secret = ECC.ECC.derive_key_function(kwargs["private_key"], client_key)
            return shared_secret
        if protocol == "ElGamal":
            client_public_key = await websocket.recv()
            client_public_key = json.loads(client_public_key)
            await websocket.send(json.dumps(kwargs["public_key"]))
            return client_public_key

class Keys:
    @staticmethod
    def get_public_key(protocol):
        secret = json.loads(open("./server_utils/server_secret.json", "r").read())
        if protocol not in secret.keys():
            if protocol == "RSA":
                pub, priv = RSA.generateRSAkeys()
            if protocol == "ECC":
                priv, pub = ECC.ECC.generate_keys()
            if protocol == "ElGamal":
                priv, pub = ElGamal.generate_keys()
            secret[protocol] = {}
            secret[protocol]["private_key"] = priv
            if protocol == "RSA":
                secret[protocol]["public_key"] = pub
            if protocol == "ECC":
                secret[protocol]["public_key"] = {"x":pub.x, "y":pub.y}
            if protocol == "ElGamal":
                secret[protocol]["private_key"] = priv
                secret[protocol]["public_key"] = {"q":pub[0], "h":pub[1], "g":pub[2]}
            with open("./server_utils/server_secret.json", "w") as file:
                file.write(json.dumps(secret, indent=4))
            return pub
        else:
            return secret[protocol]["public_key"]
    @staticmethod
    def get_private_key(protocol):
        secret = json.loads(open("./server_utils/server_secret.json", "r").read())
        if protocol not in secret.keys():
            if protocol == "RSA":
                pub, priv = RSA.generateRSAkeys()
            if protocol == "ECC":
                priv, pub = ECC.ECC.generate_keys()
            if protocol == "ElGamal":
                priv, pub = ElGamal.generate_keys()
            secret[protocol] = {}
            secret[protocol]["private_key"] = priv
            if protocol == "RSA":
                secret[protocol]["public_key"] = pub
            if protocol == "ECC":
                secret[protocol]["public_key"] = {"x":pub.x, "y":pub.y}
            if protocol == "ElGamal":
                secret[protocol]["public_key"] = pub
                secret[protocol]["private_key"] = {"q":priv[0], "h":priv[1], "g":priv[2]}
            with open("./server_utils/server_secret.json", "w") as file:
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
        _logger.log(f"Encryption protocol: {self.config.encrypt}", 0)
        _logger.log(f"Database path: {self.config.db_path}", 0)
        _logger.log(f"Host: {self.config.host}", 0)
        _logger.log(f"Port: {self.config.port}", 0)
        _logger.log(f"Keys: {self.keys}", 1)


    def run(self):
        _logger.log("Server started", 0)
        start_server = websockets.serve(self.connect, self.config.host, self.config.port, ping_interval=30, ping_timeout=120)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()
    
    async def send_message(self, message):
        message = json.dumps(message)
        for user in self.users:
            await user.send(EncDecWrapper.encrypt(message, self.config.encrypt, public_key=self.users[user][1], shared_key=self.users[user][1] if self.config.encrypt == "ECC" else None))
    
    async def handle_client(self, websocket):
        while True:
            try:
                message = await websocket.recv()
                message = EncDecWrapper.decrypt(message, self.config.encrypt, private_key=self.keys[1], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None)
                message = json.loads(message)
                _logger.log(f"Received: {message['data']}", 1)
                if hashlib.sha256(message['data'].encode('utf-8')).hexdigest() != message['hash']:
                    _logger.log(f"Message hash mismatch: {message['data']}", 3)
                    continue
                # msg = EncDecWrapper.encrypt(message['data'], self.config.encrypt, public_key=self.keys[0], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None), message['time_sent'], self.db.get_user_id(message["sender_username"]), 0, message['type'], message['hash']
                self.db.create_message(EncDecWrapper.encrypt(message['data'], self.config.encrypt, public_key=self.keys[0], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None), message['time_sent'], self.db.get_user_id(message["sender_username"]), 0, message['type'], message['hash'])
                _logger.log(f"Message saved to database: {message}", 0)
                await self.send_message(message)
            except websockets.exceptions.ConnectionClosedError:
                _logger.log(f"User {self.users[websocket][0]} disconnected", 1)
                break

    async def connect(self, websocket):
        client_key = None
        shared_secret = None
        if self.config.encrypt == "RSA":
            client_key = await EncDecWrapper.handshake("RSA", websocket, public_key=self.keys[0])
            _logger.log(f"Client key: {client_key}", 1)
        if self.config.encrypt == "ECC":
            shared_secret = await EncDecWrapper.handshake("ECC", websocket, public_key=self.keys[0], private_key=self.keys[1])
            shared_secret = shared_secret[:16]
            _logger.log(f"Shared secret: {shared_secret}", 1)
        if self.config.encrypt == "ElGamal":
            client_key = await EncDecWrapper.handshake("ElGamal", websocket, public_key=self.keys[0])
            _logger.log(f"Client key: {client_key}", 1)
        login_info = await websocket.recv()
        if self.config.encrypt == "RSA":
            login_info = EncDecWrapper.decrypt(login_info, "RSA", private_key=self.keys[1])
        if self.config.encrypt == "ECC":
            login_info = EncDecWrapper.decrypt(login_info, "ECC", shared_key=shared_secret)
            login_info = login_info.decode('utf-8').strip('\x00')
        if self.config.encrypt == "ElGamal":
            login_info = EncDecWrapper.decrypt(login_info, "ElGamal", private_key=self.keys[1])
        login_info = json.loads(login_info)

        if self.db.check_user(login_info['username'], login_info['password']):
            msg = EncDecWrapper.encrypt("Success", self.config.encrypt, public_key=client_key, shared_key=shared_secret)
            await websocket.send(msg)
            if self.config.encrypt == "RSA":
                self.users[websocket] = (login_info['username'], client_key)
            if self.config.encrypt == "ECC":
                self.users[websocket] = (login_info['username'], shared_secret)
            if self.config.encrypt == "ElGamal":
                self.users[websocket] = (login_info['username'], client_key)
            _logger.log(f"User {login_info['username']} connected", 0)
            await self.handle_client(websocket)
        else:
            await websocket.send(EncDecWrapper.encrypt("Fail", self.config.encrypt, public_key=client_key, shared_key=shared_secret))
            _logger.log(f"User {login_info['username']} failed to connect", 2)
            await websocket.close()












if __name__ == "__main__":
    with open("server_config.json", "r", encoding='utf-8') as fil:
        data = fil.read()
        config = Config(json.loads(data))
    _logger.log(f"Config: {config.__dict__}", 0)
    server = Server(config)
    # server.db.add_user("test1", hashlib.sha256("test1".encode('utf-8')).hexdigest())
    server.run()

    