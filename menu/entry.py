from utils.log import Log
import os

class Entry:
    def __init__(self):
        self.options = []

    def fetch_options(self):
        # Fetch all the .py files in "menu" dir
        for file in os.listdir("menu"):
            if file.endswith(".py") and file != "__init__.py" and file != "entry.py":
                self.options.append(file[:-3])  # Remove the .py extension