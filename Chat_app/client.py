from PyQt5.QtWidgets import QApplication, QWidget, QGraphicsDropShadowEffect, QVBoxLayout, QLabel, QLineEdit, QPushButton
import PyQt5.QtCore as QtCore
from PyQt5.QtGui import QPixmap
class RegiWinndow(QWidget):
    def __init__(self):
        super().__init__()
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
        layout.addWidget(self.register_button)
        self.setLayout(layout)

        self.show()


if __name__ == "__main__":
    app = QApplication([])
    window = RegiWinndow()
    app.exec()

    