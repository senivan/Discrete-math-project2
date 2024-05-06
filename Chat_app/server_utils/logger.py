import datetime
import os

class LogMessage:
    level_map = {
        "INFO":0,
        "WARNING":2,
        "ERROR":3,
        "CRITICAL":4
    }

    def __init__(self, message:str, level:int, time:datetime.datetime = datetime.datetime.now()):
        self.message = message
        self.level = level
        self.time = time
    
    def __str__(self):
        return f"{datetime.datetime.strftime(self.time, '%Y-%m-%d %H:%M:%S')} - {self.level_map[self.level]}: {self.message}"
    
    def __repr__(self):
        return self.__str__()


class Logger:
    def __init__(self, log_path:str, log_level:int = 3, print_log:bool = True):
        self.log_path = log_path
        self.log_level = log_level
        self.print_log = print_log
        if not os.path.exists(log_path):
            with open(log_path, "w", encoding="utf-8") as file:
                file.write(f"Log file created at {datetime.datetime.now()}\n")
    
    def log(self, message:str, level:int):
        log_message = LogMessage(message, level)
        if level < self.log_level:
            return
        if self.print_log:
            print(log_message)
        with open(self.log_path, "a", encoding="utf-8") as file:
            file.write(f"{log_message}\n")