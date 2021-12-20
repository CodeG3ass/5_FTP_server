import socket
import os
import shutil
import logging
import json
import hashlib
import binascii
from threading import Thread
from settings import  *


PORT = 1556
hom_dir = os.path.join(os.getcwd(), 'docs')
cur_dir = hom_dir

def hash_password(password: str) -> str:

    salt = hashlib.sha256(os.urandom(60)).hexdigest().encode('ascii')
    pwdhash = hashlib.pbkdf2_hmac('sha512', password.encode('utf-8'), salt, 100000)
    pwdhash = binascii.hexlify(pwdhash)
    return (salt + pwdhash).decode('ascii')


def verify_password(stored_password: str, provided_password: str) -> bool:

    salt = stored_password[:64]
    stored_password = stored_password[64:]
    pwdhash = hashlib.pbkdf2_hmac(
        'sha512',
        provided_password.encode('utf-8'),
        salt.encode('ascii'),
        100000
    )
    pwdhash = binascii.hexlify(pwdhash).decode('ascii')
    return pwdhash == stored_password


def connection_with_auth(sock):

    conn, addr = sock.accept()
    address = ':'.join([str(i) for i in addr])
    if address in data_users['users']:
        conn.send(f"Hello {data_users['users'][address]['name']}! Enter passw".encode())
        while True:
            data_password = conn.recv(1024).decode()
            if not data_password:
                conn.send(f"Incorrect passw".encode())
            else:
                if verify_password(data_users['users'][address]['password'], data_password):
                    conn.send(f"Welcome".encode())
                    break
                else:
                    conn.send(f"Incorrect passw".encode())
            conn.send("Enter passw".encode())
    else:
        conn.send(f"Name:".encode())
        data_name = conn.recv(1024).decode()
        conn.send(f"Passw:".encode())
        data_pass = conn.recv(1024).decode()
        if not data_name or not data_pass:
            conn.send(f"Incorrect".encode())
            return None, None, None
        data_users['users'][address] = {'name': data_name, 'password': hash_password(data_pass)}
        with open('data_users.json', 'w') as file:
            json.dump(data_users, file)
        conn.send(f"Welcome {data_name}. Password added".encode())
    # conn.send("Ok".encode())
    return conn, addr, data_users['users'][address]['name']


class ClientThread(Thread):
    def __init__(self, conn, addr, name):
        Thread.__init__(self)
        self.conn = conn
        self.addr = addr
        self.ip = addr[0]
        self.port = addr[1]
        self.name = name

        logger.info(f"Connect client {addr[0]}:{addr[1]}")

    def commands(self):
        return "pwd - выводит текущий путь\n" \
               "ls DIRECTORY- выводит содержимое текущего каталога\n" \
               "cd DIRECTORY- изменяет текущий каталог\n" \
               "mkdir DIRECTORY - создает каталог\n" \
               "rm PATH - удаляет файл или каталог\n" \
               "cat FILE - выводит содержимое файла\n" \
               "write FILE TEXT - записывает текст в файл\n" \
               "memory - выводит информацию о памяти" \
               "exit - разрыв соединения с сервером\n" \
               "commands - выводит справку по командам\n"

    def run(self):
        while True:
            try:
                data = self.conn.recv(1024).decode()
                if data == 'stop' or not data:
                    logger.info(f"Disconnect client {self.addr[0]}:{self.addr[1]}")
                    self.conn.close()
                    break
                else:
                    logger.info(f"From client {self.addr[0]}:{self.addr[1]} - {data}")
                    response = self.process(data)
                    logger.info(f"To client {self.addr[0]}:{self.addr[1]} - {response}")
                    try:
                        self.conn.send(response.encode())
                    except BrokenPipeError:
                        logger.info(f"Disconnect client {self.addr[0]}:{self.addr[1]}")
            except ConnectionResetError:
                self.conn.close()

    def ls(self):
        return "; ".join(os.listdir(PATH)) + "\n"

    def rm(self, path):
        if self.is_path_correct(path):
            if os.path.exists(path):
                if os.path.isdir(path):
                    shutil.rmtree(path)
                else:
                    os.remove(path)
                return "\n"
            else:
                return "Путь неверный\n"
        else:
            return "Путь неверный\n"

    def pwd(self):
        current_path = os.getcwd().replace(USER_DIRECTORY, "")
        if current_path == "":
            current_path = "\\"
        return current_path + "\n"

    def is_path_correct(self, path):
        return USER_DIRECTORY in os.path.abspath(path) or USER_IS_ADMIN

    def cd(self, path, ignore_limitation=False):
        global PATH
        path = USER_DIRECTORY if path == "~" else path
        if self.is_path_correct(path) or ignore_limitation is True:
            if os.path.isdir(path):
                os.chdir(path)
                PATH = os.getcwd()
                return "\n"
            else:
                return "Путь неверный\n"
        else:
            return "Путь неверный\n"

    def get_dir_size(self, directory):
        directory_size = 0
        for path, directories, files in os.walk(directory):
            for directory in directories:
                directory_size += self.get_dir_size(os.path.join(path, directory))
            for file in files:
                directory_size += os.path.getsize(os.path.join(path, file))
        return directory_size

    def check_directory_size(self):
        return self.get_dir_size(USER_DIRECTORY) > MAX_SIZE

    def mkdir(self, path):
        if self.is_path_correct(path) or USER_IS_ADMIN:
            os.mkdir(path)
            return "\n"
        else:
            return "Путь неверный\n"

    def create_user_directory(self, login):
        global USER_DIRECTORY, PATH
        if not (os.path.exists(USER_DIRECTORY + os.sep + login) and os.path.isdir(USER_DIRECTORY + os.sep + login)):
            os.mkdir(login)
        USER_DIRECTORY = USER_DIRECTORY + os.sep + login
        PATH = USER_DIRECTORY
        self.cd(login, True)
    def write(self, *args):
        path = args[0]
        content = " ".join(args[1:])
        if os.path.isfile(path):
            if self.is_path_correct(path):
                with open(path, "r") as file:
                    temp_text = file.read()
                with open(path, "a") as file:
                    file.write(content)
                if self.check_directory_size():
                    with open(path, "w") as file:
                        content = temp_text.replace(content, "", (temp_text.count(content) - 1))
                        file.write(content)
                        return "Не хватает места\n"
                return "\n"
            else:
                return "Путь неверный\n"
        else:
            return "Путь неверный\n"
    def process(self, req):
        global cur_dir
        global hom_dir
        try:
            bool_var = False
            for i in ['pwd', 'ls', 'cat', 'mkdir', 'remdir', 'rm', 'rename', 'sends', 'sendc', 'cd']:
                if req.startswith(i):
                    bool_var = True
                    break
            assert bool_var, "Incorrect command"
            if req == 'pwd':
                return self.pwd()

            elif req == 'ls':
                return self.ls

            elif req[:3] == 'cat':
                filename = req[4:]
                if filename not in os.listdir(cur_dir):
                    return "Dir doesnt exist"
                else:
                    with open(os.path.join(cur_dir, filename), 'r', encoding='utf-8') as f:
                        inner = f.read()
                        return inner
            elif req[:5]=='write':
                self.write(req[6:])

            elif req[:5] == 'mkdir':
                filename = req[6:]
                if filename in os.listdir(cur_dir):
                    return "Dir doesnt exist"
                else:
                    self.mkdir(filename)

            elif req[:2] == 'rm':
                filename = req[3:]
                return self.rm(filename)

            elif req[:6] == 'rename':
                lst = list(req.split())
                if len(lst) != 3:
                    return "Incorrect args"
                else:
                    if lst[1] not in os.listdir(cur_dir):
                        return "File doesnt exist"
                    else:
                        os.rename(os.path.join(cur_dir, lst[1]), os.path.join(cur_dir, lst[2]))
                        return 'File ' + lst[1] + ' renamed to ' + lst[2]

            elif req[:2] == 'cd':
                path = req[3:]
                return self.cd(path)

        except AssertionError:
            return "Incorrect command"
try:
    with open("data_users.json", "r") as read_file:
        data_users = json.load(read_file)
except FileNotFoundError:
    with open("data_users.json", 'wt') as write_file:
        data_users = {'users': {}}
        json.dump(data_users, write_file)
logger = logging.getLogger("serverLogger")
logger.setLevel(logging.INFO)
fh = logging.FileHandler("server.log")
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', PORT))
threads = []
while True:
    sock.listen()
    clientsock, clientAddress, name = connection_with_auth(sock)
    newthread = ClientThread(clientsock, clientAddress, name)
    newthread.start()

conn.close()
sock.close()