from PyQt5.QtWidgets import QApplication, QWidget, QGraphicsDropShadowEffect, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QGridLayout, QScrollArea, QPlainTextEdit, QHBoxLayout, QDialog, QFileDialog
# from PyQt5.QtWidgets import QDesktopWidget
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QPixmap, QMovie
import websockets
# from PyQt5 import QtWebSockets
# import tkinter as tk
import wx
# import websockets
from PyQt5.QtCore import QThread, pyqtSignal
import asyncio
import json
import os
import hashlib
import sys
from datetime import datetime
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
    class Message:
        def __init__(self, data, time_sent, sender_username, type, hash):
            self.data = data
            self.time_sent = time_sent
            self.sender_username = sender_username
            self.type = type
            self.hash = hash

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
        self.server = "ws://localhost:8000"
        self.listener = None
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
    
    async def listen(self):
        while True:
            message = await self.websocket.recv()
            message = EncDecWrapper.decrypt(message, self.comm_protocol, private_key=self.private_key, public_key=self.server_public_key)
            message = json.loads(message)
            _logger.log(f"Received: {message['data']} from {message['sender_username']} at {message['time_sent']}", 0)
            self.message.emit(message)
            _logger.log("Emitted message", 0)
            # self.parent().create_bubble(message['data'], message['time_sent'], message['sender_username'])
            # await asyncio.sleep(0.1)

    def send_message(self, message, type="txt"):
        # self.websocket.send(EncDecWrapper.encrypt(message, self.comm_protocol, public_key=self.server_public_key))
        to_send = self.Message(message, datetime.now().strftime("%Y-%m-%d-%H-%M"), self.username, type, hashlib.sha256(message.encode('utf-8')).hexdigest())
        _logger.log(f"Sent: {message}", 0)
        asyncio.run(self.websocket.send(EncDecWrapper.encrypt(json.dumps(to_send.__dict__), self.comm_protocol, public_key=self.server_public_key)))
        
class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__()
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
        self.chats_wrapper.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; max-width: 450px; margin-top: 10px;")
        grid.addWidget(self.chats_wrapper, 1, 0)

        self.all_chats_data = {}
        self.add_chat = QPushButton("Add Chat", self)
        self.add_chat.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 15px; padding: 10px; border-radius: 10px; max-width: 450px;")
        self.add_chat.clicked.connect(self.new_chat)
        grid.addWidget(self.add_chat, 2, 0)

        # self.message_box = QGridLayout()
        # self.message_box.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px;margin-left: 10 px; margin-right: 4px; padding: 10px; border-radius: 10px;")
        

        # self.wrapper = QWidget()
        # self.message_box = QGridLayout()
        # self.create_bubble("Hello", "User")
        # self.wrapper.setLayout(self.message_box)
        # scroll = QScrollArea()
        # scroll.setWidget(self.wrapper)
        # scroll.setWidgetResizable(True)
        # # label1 = QLabel("Message1", self.wrapper)
        # # label2 = QLabel("Message2", self.wrapper)
        # # label3 = QLabel("Message3", self.wrapper)
        # # label4 = QLabel("Message4", self.wrapper)
        # # label5 = QLabel("Message5", self.wrapper)
        # # label6 = QLabel("Message6", self.wrapper)
        # # self.message_box.addWidget(label1, 0, 1, 2, 2)
        # # self.message_box.addWidget(label2, 1, 1, 2, 2)
        # # self.message_box.addWidget(label3, 2, 1, 2, 2)
        # # self.message_box.addWidget(label4, 3, 1, 2, 2)
        # # self.message_box.addWidget(label5, 4, 1, 2, 2)
        # # self.message_box.addWidget(label6, 5, 1, 2, 2)
        # grid.addWidget(self.wrapper, 0, 1, 2, 2)

        # self.message_box = QPlainTextEdit(self)
        # self.message_box.setReadOnly(True)
        # self.message_box.setPlaceholderText("Messages")
        # self.message_box.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        # self.message_box.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px;")
        # grid.addWidget(self.message_box, 0, 1, 2, 2)


        self.wrapper = QWidget()
        self.message_box = QVBoxLayout()
        self.message_box.setAlignment(QtCore.Qt.AlignBottom | QtCore.Qt.AlignLeft)
        # self.create_bubble("Hello", "12:00", "User")
        # self.create_bubble("flkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadojflkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadojflkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadojflkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadojflkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadojflkjldafjpodajfpsdajfpjdspfjpadfjpdsjfpajdjfpadoj", "12:00", "User")
        self.wrapper.setLayout(self.message_box)
        scroll = QScrollArea()
        scroll.setWidget(self.wrapper)
        scroll.setWidgetResizable(True)
        grid.addWidget(scroll, 0, 1, 2, 3)
        

        self.input_message = QLineEdit(self)
        self.input_message.setPlaceholderText("Type your message")
        self.input_message.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px;")
        self.input_message.setEnabled(False)
        grid.addWidget(self.input_message, 2, 1)

        self.media_button = QPushButton("Media", self)
        self.media_button.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px;")
        self.media_button.setEnabled(False)
        self.media_button.clicked.connect(self.send_media_message)
        grid.addWidget(self.media_button, 2, 2)


        self.send_button = QPushButton("Send", self)
        self.send_button.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; margin-right: 10px; padding: 10px; border-radius: 10px; min-width: 100px;")
        # self.send_button.setEnabled(False)
        grid.addWidget(self.send_button, 2, 3)
        self.send_button.clicked.connect(self.send_message)

        self.setLayout(grid)
        self.user_creds = self.load_creds()
        _logger.log(f"User credentials: {self.user_creds}", 0)
        self.connection = ConnectionHandler(self.user_creds[0], self.user_creds[1], self.cred_flag)

        self.connection.message.connect(self.create_bubble)

        self.connection.start()
        self.show()

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
        create_button.clicked.connect(lambda: self.generate_chat(chat_name_input.text()))
        create_button.clicked.connect(lambda: self.all_chats_data.update({chat_name_input.text():usernames_input.text().split(";")}))
        create_button.clicked.connect(dialog.close)
        dialog.exec_()
        # chat_name = chat_name_input.text()
        # usernames_res = usernames_input.text().split(";")
        # self.all_chats_data[chat_name] = usernames_res

    def generate_chat(self, chat_name):
        chat = QPushButton(chat_name, self.chats_wrapper)
        chat.setCheckable(True)
        chat.clicked.connect(self.chat_clicked)
        chat.setStyleSheet("background-color: black; color: #4CAF50; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; text-align: left; min-height: 50px;")
        self.chats.addWidget(chat)

    def chat_clicked(self):
        for button in self.chats_wrapper.findChildren(QPushButton):
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

    def generate_chat_mesasages(self):
        for button in self.chats_wrapper.findChildren(QPushButton):
            if self.sender().isChecked():
                self.clear_message_box()
                # Perform other actions when chat is toggle
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
        # self.message_box1.setAlignment(QtCore.Qt.AlignLeft)
        self.message_box1.setAlignment(QtCore.Qt.AlignBottom | QtCore.Qt.AlignLeft)

        # self.message_box1.addStretch(0)
        self.username = QLabel(user+": ", self.wrapper1)
        self.username.setStyleSheet("color: #4CAF50; font-size: 18px; font-weight: bold;")
        # self.username.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
        self.bubble = QWidget()
        self.bubble.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
        
        grid = QGridLayout()
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(0)
        if msg.endswith(".png") or msg.endswith(".jpg") or msg.endswith(".jpeg"):
            self.image = QLabel(self.bubble)
            pixmap = QPixmap(msg)
            # pixmap = pixmap.scaled(200, 200)
            pixmap = pixmap.scaledToWidth(600)
            self.image.setPixmap(pixmap)
            grid.addWidget(self.image, 0, 0, 0, 1)
        elif msg.endswith(".gif"):
            self.gif = QMovie(msg)
            self.gif_label = QLabel(self.bubble)
            self.gif_label.setMovie(self.gif)
            self.gif.start()
            grid.addWidget(self.gif_label, 0, 0, 0, 1)
        else:
            self.message = QLabel(msg, self.bubble)
            self.message.setWordWrap(True)
        # self.message.setReadOnly(True)
            self.message.setStyleSheet("background-color: #4CAF50; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px;")
            grid.addWidget(self.message, 0, 0, 0, 1)
        self.time = QLabel(time, self.bubble)
        self.time.setStyleSheet("background-color: #4CAF50; color: black; font-size: 14px; margin-left: 10px; padding: 10px; border-radius: 10px;")
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
        self.input_message.setText("")
        if message != "":
            msg = {"data":message, "time_sent":datetime.strftime(datetime.now(), "%H:%M"), "sender_username":self.user_creds[0]}
            self.create_bubble(msg)
        self.connection.send_message(message)
    def send_media_message(self):
        file_dialog = QFileDialog()
        file_dialog.setFileMode(QFileDialog.ExistingFile)
        file_dialog.setNameFilter("Images (*.png *.jpg *.jpeg *.gif)")
        if file_dialog.exec_():
            selected_files = file_dialog.selectedFiles()
            # Process the selected image files here
            for file in selected_files:
                # Send the image file to the server
                self.send_image(file)
    
    def send_image(self, file):
        msg = {"data":file, "time_sent":datetime.strftime(datetime.now(), "%H:%M"), "sender_username":self.user_creds[0]}
        self.create_bubble(msg)

    # async def connect_to_server(self, username, password, register=False):
    #     async with websockets.connect("ws://localhost:8000") as websocket:
    #         await websocket.send("Initiate handshake")
    #         global public_key, private_key, comm_protocol
    #         comm_protocol = await websocket.recv()
    #         comm_protocol = json.loads(comm_protocol)
    #         _logger.log(f"Communication protocol: {comm_protocol}", 0)
    #         private_key, public_key = EncDecWrapper.generate_keys(comm_protocol)
    #         global server_public_key
    #         server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key, private_key=private_key)
    #         # print(f"Server public key: {server_public_key}")
    #         # print(f"Client private key: {private_key}")
    #         # print(f"Client public key: {public_key}")
    #         # print(f"Communication protocol: {comm_protocol}")
    #         # print("Connected to server")
    #         # print(self.user_creds)
    #         _logger.log(f"Server public key: {server_public_key}", 0)
    #         _logger.log(f"Client public key: {public_key}", 0)
    #         _logger.log("Connected to server", 0)
    #         msg = json.dumps({"username":username, "password":password, "register":not register})
    #         _logger.log(f"Sending: {msg}", 0)
    #         await websocket.send(EncDecWrapper.encrypt(msg, comm_protocol, public_key=server_public_key))
    #         response = await websocket.recv()
    #         response = EncDecWrapper.decrypt(response, comm_protocol, private_key=private_key, public_key=server_public_key)
    #         _logger.log(f"Received: {response}", 0)
    #         if response == "Success":
    #             _logger.log("Login successful", 0)
    #             # while True:
    #             #     await asyncio.sleep(0.1)
    #         else:
    #             self.close()

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()
    sys.exit(app.exec_())