from PyQt5.QtWidgets import QApplication, QWidget, QGraphicsDropShadowEffect, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QGridLayout, QHBoxLayout
# from PyQt5.QtWidgets import QDesktopWidget
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QPixmap
# import tkinter as tk
import websockets
import asyncio
import json
import os
import hashlib
from Encryption_algos import RSA, ECC, ElGamal

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
            print(f"Server public key: {server_}")
            print(f"Client private key: {kwargs['private_key']}")
            server_ = ECC.Point(server_["x"], server_["y"])
            priv = kwargs["private_key"]
            print(type(priv), type(server_))
            shared_secret = ECC.ECC.derive_key_function(priv, server_)
            print(f"Shared secret: {shared_secret}")
            return shared_secret
        if protocol == "ElGamal":
            msg = json.dumps(kwargs["public_key"])
            await websocket.send(msg)
            server_ = await websocket.recv()
            server_ = json.loads(server_)
            return server_
    
    # @staticmethod
    # async def connect_to_server():
        # async with websockets.connect("ws://localhost:8000") as websocket:
        #     await websocket.send("Initiate handshake")
        #     global public_key, private_key, comm_protocol
        #     comm_protocol = await websocket.recv()
        #     comm_protocol = json.loads(comm_protocol)
        #     public_key, private_key = EncDecWrapper.generate_keys(comm_protocol)
        #     global server_public_key
        #     server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key, private_key=private_key)

class RegiWinndow(QWidget):
    def __init__(self):
        super().__init__()
        print("Registering")
        self.setWindowTitle("Register")
        # self.setGeometry(100, 100, 400, 400)
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
        print("Opening main window")
    
    def error_popup(self):
        popup = QMessageBox()
        popup.setWindowTitle("Registration Unsuccessful")
        popup.setText("Please check your credentials and try again.")
        popup.setIcon(QMessageBox.Critical)
        popup.exec_()

    def check_fields(self):
        if self.password.text() == self.con_password.text() and self.username.text() != "" and self.password.text() != "":
            return True
        return False

class MainWindow(QWidget):
    def __init__(self) -> None:
        super().__init__() 
        self.setWindowTitle("Chat")
        self.setFixedSize(1920, 1080)
        self.shadow = QGraphicsDropShadowEffect()
        self.shadow.setBlurRadius(20)
        self.shadow.setXOffset(0)
        self.shadow.setYOffset(0)
        self.shadow.setColor(QtCore.Qt.GlobalColor.black)
        self.setGraphicsEffect(self.shadow)
        self.setWindowOpacity(0.9)
        self.setStyleSheet("background-color: rgba(0, 0, 0, 0.9);")
        
        box = QHBoxLayout()
        box.setSpacing(0)
        box.setContentsMargins(0, 0, 0, 0)
       
        self.label = QLabel("Chat", self)
        self.label.setStyleSheet("color: white; max-height:100px; font-size: 20px; max-width:450px; margin-left: 50px; padding: 10px; text-align: center; background-color: transperent; border-radius: 10px; margin-top: 10px;")
        pixmap = QPixmap("kryptos1.png")
        pixmap = pixmap.scaled(450, 90)
        self.label.setPixmap(pixmap)
        box.addWidget(self.label, 1, QtCore.Qt.AlignmentFlag.AlignLeft)

        self.chats = QLabel(self)
        self.chats.setStyleSheet("background-color: white; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; max-width: 450px;")
        box.addWidget(self.chats, 1, QtCore.Qt.AlignmentFlag.AlignLeft)

        self.message_box = QLabel(self)
        self.message_box.setStyleSheet("background-color: white; color: black; font-size: 20px; margin-right: 50px; padding: 10px; border-radius: 10px; max-width: 450px; ")
        box.addWidget(self.message_box, 1, QtCore.Qt.AlignmentFlag.AlignRight)

        
        self.setLayout(box)
        

        # self.label = QLabel("Chat", self)
        # self.label.setStyleSheet("color: white; max-height:100px; font-size: 20px; max-width:450px; margin-left: 10px; padding: 10px; text-align: center ;background-color: transperent; border-radius: 10px; margin-top: 0 px;")
        # pixmap = QPixmap("kryptos1.png")
        # pixmap = pixmap.scaled(450, 90)
        # self.label.setPixmap(pixmap)
        # grid.addWidget(self.label)

        # self.chats = QLabel(self)
        # self.chats.setStyleSheet("background-color: white; color: black; font-size: 20px; margin-left: 10px; padding: 10px; border-radius: 10px; max-width: 450px;")
        # grid.addWidget(self.chats)

        # self.message_box = QLabel(self)
        # self.message_box.setStyleSheet("background-color: white; color: black; font-size: 20px; margin-right: 50px; padding: 10px; border-radius: 10px; max-width: 450px; ")
        # grid.addWidget(self.message_box)

        # self.message = QLineEdit(self)
        # self.message.setPlaceholderText("Message")
        # self.message.setStyleSheet("background-color: white; color: black; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px; border-radius: 10px;")
        # grid.addWidget(self.message)

        # self.send_button = QPushButton("Send", self)
        # self.send_button.setStyleSheet("background-color: #4CAF50; color: white; font-size: 20px; margin-left: 50px; margin-right: 50px; padding: 10px; border-radius: 10px;")
        # grid.addWidget(self.send_button)
        
        # self.setLayout(grid)
        self.user_creds = self.load_creds()
        
        self.show()
        asyncio.run(self.connect_to_server())

    def load_creds(self):
        print("Loading creds")
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
        print(dct)
        return dct['username'], dct['password']
    
    async def connect_to_server(self):
        async with websockets.connect("ws://localhost:8000") as websocket:
            await websocket.send("Initiate handshake")
            global public_key, private_key, comm_protocol
            comm_protocol = await websocket.recv()
            comm_protocol = json.loads(comm_protocol)
            print(f"Communication protocol: {comm_protocol}")
            private_key, public_key = EncDecWrapper.generate_keys(comm_protocol)
            global server_public_key
            server_public_key = await EncDecWrapper.handshake(comm_protocol, websocket, public_key=public_key, private_key=private_key)
            print(f"Server public key: {server_public_key}")
            print(f"Client private key: {private_key}")
            print(f"Client public key: {public_key}")
            print(f"Communication protocol: {comm_protocol}")
            print("Connected to server")
            print(self.user_creds)
            msg = json.dumps({"username":self.user_creds[0], "password":self.user_creds[1], "register":not self.cred_flag})
            print(f"Sending: {msg}")
            await websocket.send(EncDecWrapper.encrypt(msg, comm_protocol, public_key=server_public_key))
            response = await websocket.recv()
            response = EncDecWrapper.decrypt(response, comm_protocol, private_key=private_key, public_key=server_public_key)
            print(f"Received: {response}")
            if response == "Success":
                print("Login successful")
            else:
                self.close()
            while True:
                await asyncio.sleep(0.1)

if __name__ == "__main__":
    app = QApplication([])
    window = MainWindow()

    app.exec()
