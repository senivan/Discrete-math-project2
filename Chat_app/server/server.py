"""
    This is the server side of the chat applications
    It should be pretty simple WebSocket server with SqlLite database
    to store the messages and user information.
    The server should be able to handle multiple clients at the same time
    and should be able to send and receive messages from the clients.
"""
import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import hashlib
import websockets
from Encryption_algos import ECC, RSA, ElGamal
from Encryption_algos.DSA import DSA
from server_utils import database, cacher
import logger


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
        # if protocol == "Rabin":
        #     return Rabin.encrypt(message, kwargs["public_key"])
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
        # if protocol == "Rabin":
        #     return Rabin.decrypt(encoded, kwargs["private_key"])
    
    @staticmethod
    async def handshake(protocol, websocket, **kwargs):
        _logger.log(f"type: {type(websocket)}", 1)
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
            # dsa exchange
            client_dsa = await websocket.recv()
            client_dsa = json.loads(client_dsa)
            await websocket.send(json.dumps(kwargs["dsa_pub"]))
            return client_key, client_dsa
        if protocol == "ECC":
            client_key = await websocket.recv()
            client_key = json.loads(client_key)
            client_key = ECC.Point(client_key["x"], client_key["y"])
            _logger.log(f"Client key: {client_key}", 1)
            await websocket.send(json.dumps(kwargs["public_key"]))
            shared_secret = ECC.ECC.derive_key_function(kwargs["private_key"], client_key)
            client_dsa = await websocket.recv()
            client_dsa = json.loads(client_dsa)
            await websocket.send(json.dumps(kwargs["dsa_pub"]))
            return shared_secret, client_dsa
        if protocol == "ElGamal":
            client_public_key = await websocket.recv()
            client_public_key = json.loads(client_public_key)
            await websocket.send(json.dumps(kwargs["public_key"]))
            client_dsa = await websocket.recv()
            client_dsa = json.loads(client_dsa)
            await websocket.send(json.dumps(kwargs["dsa_pub"]))
            return client_public_key, client_dsa

class Message:
    def __init__(self, data, time_sent, sender_username, type, hash):
        self.data = data
        self.time_sent = time_sent
        self.sender_username = sender_username
        self.type = type
        self.hash = hash
        self.chat_id = None
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
            # if protocol == "Rabin":
            #     priv, pub = Rabin.gen_keys(256)
            secret[protocol] = {}
            secret[protocol]["private_key"] = priv
            if protocol == "RSA":
                secret[protocol]["public_key"] = pub
            if protocol == "ECC":
                secret[protocol]["public_key"] = {"x":pub.x, "y":pub.y}
            if protocol == "ElGamal":
                secret[protocol]["private_key"] = priv
                secret[protocol]["public_key"] = {"q":pub[0], "h":pub[1], "g":pub[2]}
            # if protocol == "Rabin":
            #     secret[protocol]["public_key"] = pub
            #     secret[protocol]["private_key"] = {"p":priv[0], "q":priv[1]}
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
            # if protocol == "Rabin":
            #     priv, pub = Rabin.gen_keys(256)
            secret[protocol] = {}
            secret[protocol]["private_key"] = priv
            if protocol == "RSA":
                secret[protocol]["public_key"] = pub
            if protocol == "ECC":
                secret[protocol]["public_key"] = {"x":pub.x, "y":pub.y}
            if protocol == "ElGamal":
                secret[protocol]["public_key"] = pub
                secret[protocol]["private_key"] = {"q":priv[0], "h":priv[1], "g":priv[2]}
            # if protocol == "Rabin":
            #     secret[protocol]["public_key"] = pub
            #     secret[protocol]["private_key"] = {"p":priv[0], "q":priv[1]}
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
        self.log_level = conf["debug_level"]

class Server:
    def __init__(self, config:'Config'):
        self.config = config
        self.db = database.Database()
        self.users = {}
        self.keys = (Keys.get_public_key(self.config.encrypt), Keys.get_private_key(self.config.encrypt))
        rsa = RSA.generateRSAkeys(32)
        self.dsa_keys = (rsa[1], rsa[0])
        self.thread_pool = ThreadPoolExecutor()
        self.requests = []
        self.requests_cache = cacher.Cache(500)
        _logger.log(f"Encryption protocol: {self.config.encrypt}", 0)
        _logger.log(f"Database path: {self.config.db_path}", 0)
        _logger.log(f"Host: {self.config.host}", 0)
        _logger.log(f"Port: {self.config.port}", 0)
        _logger.log(f"Keys: {self.keys}", 1)
        _logger.log(f"DSA keys: {self.dsa_keys}", 1)


    def run(self):
        _logger.log("Server started", 0)
        start_server = websockets.serve(self.connect, self.config.host, self.config.port, ping_interval=30, ping_timeout=120)
        asyncio.get_event_loop().run_until_complete(start_server)
        asyncio.get_event_loop().run_forever()
    
    async def send_message(self, message):
        message_chat = message['chat_id']
        chat_participants = self.db.get_chat_participants(message_chat)
        _logger.log(f"Chat participants: {chat_participants}", 1)
        # message['hash'] = DSA.sign(message['data'], self.dsa_keys[1])
        to_send = message.copy()
        to_send['hash'] = DSA.sign(message['data'], self.dsa_keys[0])
        for participant in chat_participants:
            try:
                part_websocket = [key for key, value in self.users.items() if value[0] == participant][0]
                if part_websocket in self.users.keys() and participant != to_send['sender_username']:
                    await part_websocket.send(EncDecWrapper.encrypt(json.dumps(to_send), self.config.encrypt, public_key=self.users[part_websocket][1], shared_key=self.users[part_websocket][1] if self.config.encrypt == "ECC" else None))
                    _logger.log(f"Sent: {to_send} to {participant}", 1)
                    _logger.log(f"Signed: {DSA.verify(to_send['data'], to_send['hash'], self.dsa_keys[1])}", 1)
            except Exception as e:
                _logger.log(f"Error: {e}", 3)
        
    
    async def handle_client(self, websocket):
        async def txt_img_hadler(message):
            self.db.create_message(message["data"], message["time_sent"], self.db.get_user_id(message["sender_username"]), message["chat_id"], message["type"], message["hash"])
            _logger.log(f"Message saved to database: {message}", 0)
            await self.send_message(message)
            self.requests.remove(message)
        async def send_helper(message, participant):
            try:
                part_websocket = [key for key, value in self.users.items() if value[0] == participant][0]
                _logger.log(f"Sending chat update to {part_websocket}", 0)
                if part_websocket in self.users.keys():
                    _logger.log(f"Sending chat update to {self.users[part_websocket]}", 0)
                    chats = self.db.get_chats(participant)
                    to_send = json.dumps({"chat_update":[chat.__dict__ for chat in chats]})
                    await part_websocket.send(EncDecWrapper.encrypt(to_send, self.config.encrypt, public_key=self.users[part_websocket][1], shared_key=self.users[part_websocket][1] if self.config.encrypt == "ECC" else None))
            except Exception as e:
                _logger.log(f"Error: {e}", 3)
        def send_helper_sync(message, participant):
            asyncio.run(send_helper(message, participant))
        async def com_handler(message):
            # if message in self.requests_cache.cache.keys():
            #     await websocket.send(EncDecWrapper.encrypt(self.requests_cache.get(message), self.config.encrypt, public_key=self.users[websocket][1], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None))
            if "get_chat_history" in message['data']:
                _logger.log(f"Getting chat history", 0)
                chat_id = json.loads(message['data'])['get_chat_history']
                messages = self.db.get_all_chat_messages(chat_id)
                _logger.log(f"Messages: {messages}", 0)
                res = []
                for msg in messages:
                    res.append(Message(msg.data, msg.time_sent, self.db.get_username(msg.sender_id), msg.type, msg.hash))
                to_send = {"chat_history":json.dumps([msg.__dict__ for msg in res])}
                to_send = json.dumps(to_send)
                _logger.log(f"Sending messages: {to_send}", 0)
                await websocket.send(EncDecWrapper.encrypt(to_send, self.config.encrypt, public_key=self.users[websocket][1], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None))
                self.requests_cache[message] = to_send
            elif message['data'] == "get_chats":
                chats = self.db.get_chats(message['sender_username'])
                _logger.log(f"Chats: {chats}", 0)
                to_send = json.dumps([chat.__dict__ for chat in chats])
                _logger.log(f"Sending chats: {to_send}", 0)
                await websocket.send(EncDecWrapper.encrypt(to_send, self.config.encrypt, public_key=self.users[websocket][1], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None))
                self.requests_cache[message] = to_send
            elif "create_chat" in message['data']:
                chat_data = json.loads(message['data'])
                chat_data = chat_data['create_chat']
                participants = chat_data['participants'].split(";")
                _logger.log(f"Creating chat: {chat_data} with {participants}", 0)
                self.db.add_chat(participants,"", chat_data['name'])
                _logger.log(f"{self.users.keys()}", 0)
                for participant in participants:
                    self.thread_pool.submit(send_helper_sync, message, participant)
            elif message['data'] == 'delete':
                _logger.log(f"Deleting user: {self.users[websocket][0]}", 0)
                self.db.delete_user(self.users[websocket][0])
                del self.users[websocket]
            
            self.requests.remove(message)
        
        def txt_img_handler_sync(message):
            asyncio.run(txt_img_hadler(message))
        def com_handler_sync(message):
            asyncio.run(com_handler(message))
        while True:
            try:
                message = await websocket.recv()
                message = EncDecWrapper.decrypt(message, self.config.encrypt, private_key=self.keys[1], shared_key=self.users[websocket][1] if self.config.encrypt == "ECC" else None)
                message = json.loads(message)
                _logger.log(f"Received: {message['data']}", 1)
                # if hashlib.sha256(message['data'].encode('utf-8')).hexdigest() != message['hash']:
                #     _logger.log(f"Message hash mismatch: {message['data']}", 3)
                #     continue
                if not DSA.verify(message['data'], message['hash'], self.users[websocket][2]):
                    _logger.log(f"Message hash mismatch: {message['data']}", 3)
                    continue
                self.requests.append(message)
                if message['type'] == "txt" or message['type'] == "img":
                    self.thread_pool.submit(txt_img_handler_sync, message)                    
                elif message['type'] == 'com':
                    self.thread_pool.submit(com_handler_sync, message)
            except websockets.exceptions.ConnectionClosedError:
                _logger.log(f"User {self.users[websocket][0]} disconnected", 1)
                del self.users[websocket]
                break


    async def connect(self, websocket):
        client_key = None
        shared_secret = None
        if self.config.encrypt == "RSA":
            client_key, client_dsa = await EncDecWrapper.handshake("RSA", websocket, public_key=self.keys[0], dsa_pub=self.dsa_keys[1])
            _logger.log(f"Client key: {client_key}", 1)
        if self.config.encrypt == "ECC":
            shared_secret, client_dsa = await EncDecWrapper.handshake("ECC", websocket, public_key=self.keys[0], private_key=self.keys[1], dsa_pub=self.dsa_keys[1])
            shared_secret = shared_secret[:16]
            _logger.log(f"Shared secret: {shared_secret}", 1)
        if self.config.encrypt == "ElGamal":
            client_key, client_dsa = await EncDecWrapper.handshake("ElGamal", websocket, public_key=self.keys[0], dsa_pub=self.dsa_keys[1])
            _logger.log(f"Client key: {client_key}", 1)
        login_info = await websocket.recv()
        if self.config.encrypt == "RSA":
            login_info = EncDecWrapper.decrypt(login_info, "RSA", private_key=self.keys[1])
        if self.config.encrypt == "ECC":
            login_info = EncDecWrapper.decrypt(login_info, "ECC", shared_key=shared_secret)
        if self.config.encrypt == "ElGamal":
            login_info = EncDecWrapper.decrypt(login_info, "ElGamal", private_key=self.keys[1])
        login_info = json.loads(login_info)
        if login_info['username'] in self.users.keys():
            await websocket.send(EncDecWrapper.encrypt("Fail", self.config.encrypt, public_key=client_key, shared_key=shared_secret))
            await websocket.close()
        if login_info['register'] == True:
            if self.db.add_user(login_info['username'], login_info['password']):
                msg = EncDecWrapper.encrypt("Success", self.config.encrypt, public_key=client_key, shared_key=shared_secret)
                await websocket.send(msg)
                if self.config.encrypt == "RSA":
                    self.users[websocket] = (login_info['username'], client_key, client_dsa)
                if self.config.encrypt == "ECC":
                    self.users[websocket] = (login_info['username'], shared_secret, client_dsa)
                if self.config.encrypt == "ElGamal":
                    self.users[websocket] = (login_info['username'], client_key, client_dsa)
                _logger.log(f"User {login_info['username']} connected", 0)
                await self.handle_client(websocket)
            else:
                await websocket.send(EncDecWrapper.encrypt("Fail", self.config.encrypt, public_key=client_key, shared_key=shared_secret))
                _logger.log(f"User {login_info['username']} failed to connect", 2)
                await websocket.close()
        else:
            if self.db.check_user(login_info['username'], login_info['password']):
                msg = EncDecWrapper.encrypt("Success", self.config.encrypt, public_key=client_key, shared_key=shared_secret)
                await websocket.send(msg)
                if self.config.encrypt == "RSA":
                    self.users[websocket] = (login_info['username'], client_key, client_dsa)
                if self.config.encrypt == "ECC":
                    self.users[websocket] = (login_info['username'], shared_secret, client_dsa)
                if self.config.encrypt == "ElGamal":
                    self.users[websocket] = (login_info['username'], client_key, client_dsa)
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
    global _logger
    _logger = logger.Logger("./server_utils/server.log", config.log_level, True)
    _logger.log(f"Config: {config.__dict__}", 0)
    server = Server(config)
    # server.db.cleanup()
    server.run()