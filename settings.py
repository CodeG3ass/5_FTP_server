import os
import shutil
import socket
from datetime import datetime
DELIMITER = os.sep
MAIN_DIRECTORY = os.getcwd() + DELIMITER + "docs"
LOG = MAIN_DIRECTORY + DELIMITER + "log.txt"
USER_DIRECTORY = MAIN_DIRECTORY
PATH = USER_DIRECTORY
LOGIN = " "
ADMIN = "root"
USER_IS_ADMIN = False
MAX_SIZE = 99

