import asyncio
import json
import os
import hashlib
import sys
import base64
import lzma
from datetime import datetime
from PyQt5.QtWidgets import QApplication, QWidget, QGraphicsDropShadowEffect, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QGridLayout, QScrollArea, QPlainTextEdit, QHBoxLayout, QDialog, QFileDialog
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QPixmap
import websockets
import wx
from PyQt5.QtCore import QThread, pyqtSignal
from Encryption_algos import RSA, ECC, ElGamal
from server_utils import logger

_logger = logger.Logger("client.log", "INFO", True)
class EncDecWrapper:
    @staticmethod
    def encrypt(message, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.encrypt(message, kwargs["public_key"])
        if protocol == "ECC":
            return ECC.AES128.encrypt(kwargs["public_key"][:16], message.encode('utf-8'))
        if protocol == "ElGamal":
            res = ElGamal.encrypt(kwargs["public_key"].values(), message)
            return json.dumps(res)
    @staticmethod
    def decrypt(encoded, protocol, **kwargs):
        if protocol == "RSA":
            return RSA.decrypt(encoded, kwargs["private_key"])
        if protocol == "ECC":
            res = ECC.AES128.decrypt(kwargs["public_key"][:16], encoded)
            return res.decode('utf-8').strip('\x00')
        if protocol == "ElGamal":
            val = json.loads(encoded)
            c1, c2 = (val[0], val[1])
            return ElGamal.decrypt(kwargs["private_key"], c1, c2)
    @staticmethod
    def generate_keys(protocol):
        if protocol == "RSA":
            res = RSA.generateRSAkeys()
            return res[1], res[0]
        if protocol == "ECC":
            return ECC.ECC.generate_keys()
        if protocol == "ElGamal":
            return ElGamal.generate_keys()
    
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
            _logger.log(f"Server public key: {server_}", 0)
            _logger.log(f"Client private key: {kwargs['private_key']}", 1)
            server_ = ECC.Point(server_["x"], server_["y"])
            priv = kwargs["private_key"]
            shared_secret = ECC.ECC.derive_key_function(priv, server_)
            _logger.log(f"Shared secret:{shared_secret}", 1)
            return shared_secret
        if protocol == "ElGamal":
            msg = json.dumps(kwargs["public_key"])
            await websocket.send(msg)
            server_ =await websocket.recv()
            server_ = json.loads(server_)
            return server_
class RegiWinndow(QWidget):
    def __init__(self):
        super().__init__()
        _logger.log("Registering", 0)
        self.setWindowTitle("Register")
        self.setFixedSize(600, 600)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(20)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QtCore.Qt.GlobalColor.black)
        self.setGraphicsEffect(self.shadow)
        self.setWindowOpacity(0.9)

        layout = QVBoxLayout()
        self.setStyleSheet("background-color: rgba(0, 0, 0, 0.9);")

        self.label = QLabel("Register", self)
        self.label.setStyleSheet("color: white; max-height:100px; font-size: 20px; max-width:450px; margin-left: 50px; padding: 10px; text-align: center; background-color: transperent; border-radius: 10px; margin-top: 10px;")
        pixmap = QPixmap("kryptos1.png")
        pixmap = pixmap.scaled(450, 90)
        self.label.setPixmap(pixmap)
        
        layout.addWidget(self.label)


        self.username = QLineEdit(self)
        self.username.setPlaceholderText("Username")
        self.username.setStyleSheet("background-color: transparent; color: white; border-bottom: 1px solid white; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px;")
        self.username.setEchoMode(QLineEdit.EchoMode.Normal)
        layout.addWidget(self.username)

        self.password = QLineEdit(self)
        self.password.setPlaceholderText("Password")
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setStyleSheet("background-color: transparent; color: white; border-bottom: 1px solid white; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px;")

        layout.addWidget(self.password)

        self.con_password = QLineEdit(self)
        self.con_password.setPlaceholderText("Confim password")
        self.con_password.setEchoMode(QLineEdit.EchoMode.Password)
        self.con_password.setStyleSheet("background-color: transparent; color: white; border-bottom: 1px solid white; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px;")
        layout.addWidget(self.con_password)

        self.register_button = QPushButton("Register", self)
        self.register_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px; border-radius: 10px;")
        self.register_button.clicked.connect(self.open_popup)
        layout.addWidget(self.register_button)
        self.setLayout(layout)
        self.show()

    def open_popup(self):
        if self.check_fields():
            self.success_popup()
        else:
            self.error_popup()

    def success_popup(self):
        popup = QMessageBox()
        popup.setWindowTitle("Registration Successful")
        popup.setText("Congratulations! You have successfully registered.")
        popup.setIcon(QMessageBox.Information)
        popup.exec_()
        with open("client_secret.json", "w") as file:
            json.dump({"username":self.username.text(), "password":hashlib.sha256(self.password.text().encode('utf-8')).hexdigest()}, file)
        self.close()
        _logger.log("Registration successful", 0)
    
    def error_popup(self):
        popup = QMessageBox()
        popup.setWindowTitle("Registration Unsuccessful")
        popup.setText("Please check your credentials and try again.")
        popup.setIcon(QMessageBox.Critical)
        popup.exec_()
        _logger.log("Registration unsuccessful", 1)

    def check_fields(self):
        if self.password.text() == self.con_password.text() and self.username.text() != "" and self.password.text() != "":
            return True
        return False

outp= wx.App(False)
width, height= wx.GetDisplaySize()

class ConnectionHandler(QThread):
    message = pyqtSignal(dict)
    all_chats = pyqtSignal(list)
    all_messages = pyqtSignal(list)
    gif_res = pyqtSignal(bool)
    class Message:
        def __init__(self, data, time_sent, sender_username, type, hash, chat_id=None):
            self.data = data
            self.time_sent = time_sent
            self.sender_username = sender_username
            self.type = type
            self.hash = hash
            self.chat_id = chat_id

    def __init__(self, username, password, register=False):
        super().__init__()
        self.loop = asyncio.get_event_loop()
        self.connection = None
        _logger.log(f"User credentiols {username} {password}", 0)
        self.username = username
        self.password = password
        self.register = register
        self.server_public_key = None
        self.comm_protocol = None
        self.public_key = None
        self.private_key = None
        self.connected = False
        self.websocket = None
        self.server = "ws://74.234.5.7/"
        self._all_chats = None
        self.listener = None
        self._all_messages = None
    async def connect_to_server(self):
        self.websocket = await websockets.connect(self.server)
        await self.websocket.send("Initiate handshake")
        self.comm_protocol = await self.websocket.recv()
        self.comm_protocol = json.loads(self.comm_protocol)
        self.private_key, self.public_key = EncDecWrapper.generate_keys(self.comm_protocol)
        self.server_public_key = await EncDecWrapper.handshake(self.comm_protocol, self.websocket, public_key=self.public_key, private_key=self.private_key)
        self.connected = True
        _logger.log(f"Server public key: {self.server_public_key}", 0)
        _logger.log(f"Client public key: {self.public_key}", 0)
        _logger.log("Connected to server", 0)
        msg = json.dumps({"username":self.username, "password":self.password, "register":not self.register})
        _logger.log(f"Sending: {msg}", 0)
        await self.websocket.send(EncDecWrapper.encrypt(msg, self.comm_protocol, public_key=self.server_public_key))
        response = await self.websocket.recv()
        response = EncDecWrapper.decrypt(response, self.comm_protocol, private_key=self.private_key, public_key=self.server_public_key)
        _logger.log(f"Received: {response}", 0)
        if response == "Success":
            _logger.log("Login successful", 0)

            self._all_chats = await self._get_all_chats()
            self.all_chats.emit(self._all_chats)
            self.listener = asyncio.create_task(self.listen())
            done, pending = await asyncio.wait([self.listener], return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.sleep(0.1)
            _logger.log("Listening task created", 0)
        else:
            pass
    
    def run(self):
        self.loop.run_until_complete(self.connect_to_server())

    def create_chat(self, chat_name, participants):
        data = json.dumps({"create_chat":{"name":chat_name, "participants":";".join(participants)}})
        _logger.log(f"Sending: {data}", 0)
        msg = self.Message(data, datetime.now().strftime("%Y-%m-%d-%H-%M"), self.username, "com", hashlib.sha256(data.encode('utf-8')).hexdigest())
        asyncio.run(self.websocket.send(EncDecWrapper.encrypt(json.dumps(msg.__dict__), self.comm_protocol, public_key=self.server_public_key)))
    
    async def listen(self):
        while True:
            message = await self.websocket.recv()
            message = EncDecWrapper.decrypt(message, self.comm_protocol, private_key=self.private_key, public_key=self.server_public_key)
            message = json.loads(message)
            if 'chat_update' in message:
                _logger.log(f"Received all chats: {message}", 0)
                self._all_chats = message['chat_update']
                self.all_chats.emit(self._all_chats)
            elif 'chat_history' in message:
                _logger.log(f"Received chat history: {message['chat_history']}", 0)
                self._all_messages = message['chat_history']
                self._all_messages = json.loads(self._all_messages)
                self.all_messages.emit(self._all_messages)
            else:
                _logger.log(f"Received: {message['data']} from {message['sender_username']} at {message['time_sent']}", 0)
                self.message.emit(message)
                _logger.log("Emitted message", 0)
    
    async def _get_all_chats(self):
        msg = ConnectionHandler.Message("get_chats", datetime.now().strftime("%Y-%m-%d-%H-%M"), self.username, "com", hashlib.sha256("get_chats".encode('utf-8')).hexdigest())
        await self.websocket.send(EncDecWrapper.encrypt(json.dumps(msg.__dict__), self.comm_protocol, public_key=self.server_public_key))
        response = await self.websocket.recv()
        response = EncDecWrapper.decrypt(response, self.comm_protocol, private_key=self.private_key, public_key=self.server_public_key)
        response = json.loads(response)
        return response

    def _get_chat_history(self, chat_id):
        data = {"get_chat_history":chat_id}
        data = json.dumps(data)
        msg = ConnectionHandler.Message(data, datetime.now().strftime("%Y-%m-%d-%H-%M"), self.username, "com", hashlib.sha256(data.encode('utf-8')).hexdigest())
        asyncio.run(self.websocket.send(EncDecWrapper.encrypt(json.dumps(msg.__dict__), self.comm_protocol, public_key=self.server_public_key)))

    def get_all_chats(self):
        return self.all_chats

    def send_message(self, message):
        to_send = self.Message(message["data"], message["time_sent"], message["sender_username"], message["type"], message["hash"], message["chat_id"])
        _logger.log(f"Sent: {to_send}", 0)
        asyncio.run(self.websocket.send(EncDecWrapper.encrypt(json.dumps(to_send.__dict__), self.comm_protocol, public_key=self.server_public_key)))

    def send_delete(self):
        msg = ConnectionHandler.Message("delete", datetime.now().strftime("%Y-%m-%d-%H-%M"), self.username, "com", hashlib.sha256("delete".encode('utf-8')).hexdigest())
        asyncio.run(self.websocket.send(EncDecWrapper.encrypt(json.dumps(msg.__dict__), self.comm_protocol, public_key=self.server_public_key)))
        self.websocket.close()
        self.connected = False
        self.listener.cancel()
        _logger.log("Connection closed", 0)
class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
        self.selected_chat = None
        self.setWindowTitle("Chat")
        self.setGeometry(100, 100, width, height)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(20)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QtCore.Qt.GlobalColor.black)
        self.setGraphicsEffect(self.shadow)
        self.setWindowOpacity(0.93)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 0.9);")
        grid = QGridLayout()
        self.label = QLabel("Chat", self)
        self.label.setStyleSheet("color: white; max-height:100px; font-size: 20px; max-width:450px; margin-left: 10px; padding: 10px; text-align: center ;background-color: transperent; border-radius: 10px; margin-top: 0 px;")
        pixmap = QPixmap("kryptos1.png")
        pixmap = pixmap.scaled(450, 90)
        self.label.setPixmap(pixmap)
        grid.addWidget(self.label, 0, 0)

        self.chats_wrapper = QWidget()
        self.chats = QVBoxLayout()
        self.chats.setAlignment(QtCore.Qt.AlignTop)
        self.chats_wrapper.setLayout(self.chats)
        # self.chats_wrapper.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; max-width: 450px; margin-top: 10px;")
        scroll1 = QScrollArea()
        scroll1.setWidget(self.chats_wrapper)
        scroll1.setWidgetResizable(True)
        scroll1.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; max-width: 450px; margin-top: 10px;")
        grid.addWidget(scroll1, 1, 0)

        self.all_chats_data = {}

        buttons_box = QHBoxLayout()
        self.add_chat = QPushButton("Add Chat", self)
        self.add_chat.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 15px; padding: 10px; border-radius: 10px; max-width: 450px;")
        self.add_chat.clicked.connect(self.new_chat)
        self.account = QPushButton("Account", self)
        self.account.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 15px; padding: 10px; border-radius: 10px; max-width: 450px;")
        self.account.clicked.connect(self.about_account)
        buttons_box.addWidget(self.account)
        buttons_box.addWidget(self.add_chat)
        
        grid.addLayout(buttons_box, 2, 0)


        self.wrapper = QWidget()
        self.message_box = QVBoxLayout()
        self.message_box.setAlignment(QtCore.Qt.AlignBottom | QtCore.Qt.AlignLeft)
        self.wrapper.setLayout(self.message_box)
        scroll = QScrollArea()
        scroll.setWidget(self.wrapper)
        scroll.setWidgetResizable(True)
        scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum())
        grid.addWidget(scroll, 0, 1, 2, 3)
        

        self.input_message = QLineEdit(self)
        self.input_message.setPlaceholderText("Type your message")
        self.input_message.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px;")
        self.input_message.setEnabled(False)
        self.input_message.returnPressed.connect(self.send_message)
        grid.addWidget(self.input_message, 2, 1)

        self.media_button = QPushButton("Media", self)
        self.media_button.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px;")
        self.media_button.setEnabled(False)
        self.media_button.clicked.connect(self.send_media_message)
        grid.addWidget(self.media_button, 2, 2)


        self.send_button = QPushButton("Send", self)
        self.send_button.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px; min-width: 100px;")
        grid.addWidget(self.send_button, 2, 3)
        self.send_button.clicked.connect(self.send_message)

        self.setLayout(grid)
        self.user_creds = self.load_creds()
        _logger.log(f"User credentials: {self.user_creds}", 0)
        self.connection = ConnectionHandler(self.user_creds[0], self.user_creds[1], self.cred_flag)

        self.connection.message.connect(self.create_bubble)
        self.connection.all_chats.connect(self.generate_chats)
        self.connection.all_messages.connect(self.generate_bubbles)
        self.connection.start()
        
        # self.all_chats_data = self.connection.get_all_chats()

        self.show()
    
    def clear_chats(self):
        while self.chats.count():
            item = self.chats.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def generate_chats(self, chats):
        _logger.log(f"Chats: {chats}", 0)
        # self.clear_chats()
        for chat in chats:
            self.all_chats_data.update({chat['id']:chat['name']})
            self.generate_chat(chat['name'])

    def new_chat(self):
        dialog = QDialog(self)
        dialog.setWindowTitle("New Chat")
        layout = QVBoxLayout(dialog)
        label = QLabel("Enter chat name:", dialog)
        layout.addWidget(label)
        chat_name_input = QLineEdit(dialog)
        layout.addWidget(chat_name_input)
        usernames = QLabel("Enter usernames separated by ';' symbols:", dialog)
        layout.addWidget(usernames)
        usernames_input = QLineEdit(dialog)
        layout.addWidget(usernames_input)
        create_button = QPushButton("Create", dialog)
        layout.addWidget(create_button)
        label.setStyleSheet("color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px;")
        chat_name_input.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
        usernames.setStyleSheet("color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px;")
        usernames_input.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
        create_button.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; margin-top: 10px;")
        create_button.setEnabled(False)
        usernames_input.textChanged.connect(lambda: create_button.setEnabled(True) if chat_name_input.text() and usernames_input.text() and (str(chat_name_input.text()) not in self.all_chats_data) else create_button.setEnabled(False))
        chat_name_input.textChanged.connect(lambda: create_button.setEnabled(True) if chat_name_input.text() and usernames_input.text() and (str(chat_name_input.text()) not in self.all_chats_data) else create_button.setEnabled(False))
        _logger.log(f"Chat data: {self.all_chats_data}", 0)
        create_button.clicked.connect(lambda: self.generate_chat(chat_name_input.text()))
        create_button.clicked.connect(dialog.close)
        dialog.exec_()
        self.connection.create_chat(chat_name_input.text(), usernames_input.text().split(";")+[self.user_creds[0]])

    def about_account(self):
        dialog = QDialog(self)
        dialog.setFixedSize(400, 200)
        dialog.setWindowTitle("Account")
        dialog.setStyleSheet("background-color: rgba(0, 0, 0, 0.9); text-align: center;")
        layout = QVBoxLayout(dialog)
        label = QLabel("Username: "+self.user_creds[0], dialog)
        layout.addWidget(label)
        label.setStyleSheet("color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; text-align: center;")
        delete_button = QPushButton("Delete Account", dialog)
        layout.addWidget(delete_button)
        delete_button.setStyleSheet("background-color: #FF0000; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; margin-top: 10px;")
        delete_button.clicked.connect(lambda: self.delete_account(dialog))
        dialog.exec_()

    def delete_account(self, dialog):
        confirm_dialog = QMessageBox.question(self, "Confirmation", "Are you sure you want to delete your account?", QMessageBox.Yes | QMessageBox.No)
        if confirm_dialog == QMessageBox.Yes:
            os.remove("client_secret.json")
            self.connection.send_delete()
            dialog.close()
        else:
            dialog.close()

    def generate_chat(self, chat_name):
        chats = self.chats_wrapper.findChildren(QPushButton)
        names = [chat.text() for chat in chats]
        if chat_name in names:
            return
        chat = QPushButton(chat_name, self.chats_wrapper)
        chat.setCheckable(True)
        chat.clicked.connect(self.chat_clicked)
        chat.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: left; min-height: 50px;")
        self.chats.addWidget(chat)
    
    def generate_bubbles(self, messages):
        _logger.log(f"Messages: {messages}", 0)
        for message in messages:
            self.create_bubble(message)
    def chat_clicked(self):
        self.clear_message_box()

        for button in self.chats_wrapper.findChildren(QPushButton):
            if button == self.sender() and button.isChecked():
                self.selected_chat = button.text()
                _logger.log(f"Selected chat: {self.selected_chat}", 0)
                _logger.log(f"All chats data: {self.all_chats_data}", 0)
                chat_id = list(self.all_chats_data.keys())[list(self.all_chats_data.values()).index(self.selected_chat)]
                self.connection._get_chat_history(chat_id)
                _logger.log(f"Chat id: {chat_id}", 0)
            if button != self.sender():
                button.setChecked(False)
                button.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: left; min-height: 50px;")
        if self.sender().isChecked():
            self.sender().setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: left; min-height: 50px;")
            self.input_message.setEnabled(True)
            self.media_button.setEnabled(True)
        else:
            self.sender().setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: left; min-height: 50px;")
            self.input_message.setEnabled(False)
            self.media_button.setEnabled(False)
            self.clear_message_box()
        
        # chat_id = list(self.all_chats_data.keys())[list(self.all_chats_data.values()).index(self.selected_chat)]

    def generate_chat_mesasages(self):
        for button in self.chats_wrapper.findChildren(QPushButton):
            if self.sender().isChecked():
                self.clear_message_box()
                pass
            else:
                self.clear_message_box()

    def clear_message_box(self):
        while self.message_box.count():
            item = self.message_box.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def create_bubble(self, message):
        user = message['sender_username']
        msg = message['data']
        time = message['time_sent']
        self.wrapper1 = QWidget()
        self.message_box1 = QHBoxLayout()
        self.message_box1.setAlignment(QtCore.Qt.AlignBottom | QtCore.Qt.AlignLeft)
        self.username = QLabel(user+": ", self.wrapper1)
        self.username.setStyleSheet("color: #4CAF50; font-size: 18px; font-weight: bold;")
        self.bubble = QWidget()
        self.bubble.setMaximumWidth(self.width() // 2)
        self.bubble.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
        
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(0)
        if message['type'] == "img":
            self.image = QLabel(self.bubble)
            pixmap = QPixmap()
            pixmap.loadFromData(base64.b64decode(msg.encode('utf-8')))
            pixmap = pixmap.scaledToWidth(600)
            self.image.setPixmap(pixmap)
            grid.addWidget(self.image, 0, 0, 0, 1)
        elif message['type'] == "txt":
            self.message = QLabel(self.bubble)
            self.message.setWordWrap(True)
            self.message.setText(msg)
            self.message.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
            grid.addWidget(self.message, 0, 0, 0, 1)
        self.time = QLabel(time, self.bubble)
        self.time.setStyleSheet("background-color: #4CAF50; color: black; font-size: 14px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: bottom;")
        grid.addWidget(self.time, 1, 1)
        self.bubble.setLayout(grid)
        self.message_box1.addWidget(self.username)
        self.message_box1.addWidget(self.bubble)
        self.wrapper1.setLayout(self.message_box1)
        self.message_box.addWidget(self.wrapper1)

    def load_creds(self):
        _logger.log("Loading credentials", 0)
        self.cred_flag = True
        if not os.path.exists("client_secret.json"):
            reg = RegiWinndow()
            self.cred_flag = False
            reg.setAttribute(QtCore.Qt.WidgetAttribute.WA_DeleteOnClose)
            reg.show()
            loop = QtCore.QEventLoop()
            reg.destroyed.connect(loop.quit)
            loop.exec()
        dct = json.load(open("client_secret.json", "r"))
        return dct['username'], dct['password']
    
    def send_message(self):
        message = self.input_message.text()
        chat_id = list(self.all_chats_data.keys())[list(self.all_chats_data.values()).index(self.selected_chat)]
        self.input_message.setText("")
        msg = {"data":message, "time_sent":datetime.strftime(datetime.now(), "%Y-%m-%d-%H-%M"), "sender_username":self.user_creds[0], "chat_id":chat_id, "type":"txt", "hash":hashlib.sha256(message.encode('utf-8')).hexdigest()}
        _logger.log(f"Sending: {msg} to {chat_id}", 0)
        if message != "":
            self.create_bubble(msg)
            self.connection.send_message(msg)
    def send_media_message(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Images (*.png *.jpg *.jpeg)")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            # Process the selected image files here
            for file in selected_files:
                # Send the image file to the server
                self.send_image(file)
    
    def send_image(self, file):
        data = base64.b64encode(open(file, "rb").read()).decode('utf-8')
        chat_id = list(self.all_chats_data.keys())[list(self.all_chats_data.values()).index(self.selected_chat)]
        msg = {"data":data, "time_sent":datetime.strftime(datetime.now(), "%Y-%m-%d-%H-%M"), "sender_username":self.user_creds[0], "chat_id":chat_id, "type":"img", "hash":hashlib.sha256(data.encode('utf-8')).hexdigest()}
        self.create_bubble(msg)
        self.connection.send_message(msg)
if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    sys.exit(app.exec_())
