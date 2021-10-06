import base64
import json
import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import hidden_username, flag
import socketserver
import sys

key = os.urandom(16)
iv1 = os.urandom(16)
iv2 = os.urandom(16)

def encrypt(msg):
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    enc = aes2.encrypt(aes1.encrypt(pad(msg, 16)))
    return iv1 + iv2 + enc


def decrypt(msg):
    iv1, iv2, enc = msg[:16], msg[16:32], msg[32:]
    aes1 = AES.new(key, AES.MODE_CBC, iv1)
    aes2 = AES.new(key, AES.MODE_CBC, iv2)
    msg = unpad(aes1.decrypt(aes2.decrypt(enc)), 16)
    return msg


def create_user(requestHandler):
    requestHandler.request.sendall(b'Your username: ')
    username = requestHandler.rfile.readline().rstrip(b'\n').decode()
    if username:
        data = {"username": username, "is_admin": False}
    else:
        # Default token
        data = {"username": hidden_username, "is_admin": True}
    token = encrypt(json.dumps(data).encode())
    requestHandler.request.sendall(b"Your token: ")
    requestHandler.request.sendall(base64.b64encode(token) + b'\n')


def login(requestHandler):
    requestHandler.request.sendall(b'Your username: ')
    username = requestHandler.rfile.readline().rstrip(b'\n').decode()
    requestHandler.request.sendall(b'Your token: ')
    token = requestHandler.rfile.readline().rstrip(b'\n')
    try:
        data_raw = decrypt(base64.b64decode(token))
    except:
        requestHandler.request.sendall(b"Failed to login! Check your token again\n")
        return None

    try:
        data = json.loads(data_raw.decode())
    except:
        requestHandler.request.sendall(b"Failed to login! Your token is malformed\n")
        return None

    if "username" not in data or data["username"] != username:
        requestHandler.request.sendall(b"Failed to login! Check your username again\n")
        return None

    return data


def none_menu(requestHandler):
    requestHandler.request.sendall(b"1. Create user\n")
    requestHandler.request.sendall(b"2. Log in\n")
    requestHandler.request.sendall(b"3. Exit\n")

    try:
        requestHandler.request.sendall(b"> ")
        inp = int(requestHandler.rfile.readline().rstrip(b'\n').decode())
    except ValueError:
        requestHandler.request.sendall(b"Wrong choice!\n")
        return None

    if inp == 1:
        create_user(requestHandler)
        return None
    elif inp == 2:
        return login(requestHandler)
    elif inp == 3:
        exit(0)
    else:
        requestHandler.request.sendall(b"Wrong choice!\n")
        return None


def user_menu(user, requestHandler):
    requestHandler.request.sendall(b"1. Show flag\n")
    requestHandler.request.sendall(b"2. Log out\n")
    requestHandler.request.sendall(b"3. Exit\n")

    try:
        requestHandler.request.sendall(b"> ")
        inp = int(requestHandler.rfile.readline().rstrip(b'\n').decode())
    except ValueError:
        requestHandler.request.sendall(b"Wrong choice!\n")
        return None

    if inp == 1:
        if "is_admin" in user and user["is_admin"]:
            requestHandler.request.sendall(flag + b'\n')
        else:
            requestHandler.request.sendall(b"No.\n")
        return user
    elif inp == 2:
        return None
    elif inp == 3:
        exit(0)
    else:
        requestHandler.request.sendall(b"Wrong choice!\n")
        return None

class RequestHandler(socketserver.StreamRequestHandler):

    def handle(self):
        user = None

        self.request.sendall(b"Welcome to CBCBC flag sharing service!\n")
        self.request.sendall(b"You can get the flag free!\n")
        self.request.sendall(b"This is super-duper safe from padding oracle attacks,\n")
        self.request.sendall(b"because it's using CBC twice!\n")
        self.request.sendall(b"=====================================================\n")

        while True:
            if user:
                user = user_menu(user, self)
            else:
                user = none_menu(self)

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    pass

def main(argv):
    host, port = 'localhost', 8000

    if len(argv) == 2:
        port = int(argv[1])
    elif len(argv) >= 3:
        host, port = argv[1], int(argv[2])

    sys.stderr.write('Listening {}:{}\n'.format(host, port))
    server = ThreadedTCPServer((host, port), RequestHandler)
    server.daemon_threads = True
    server.allow_reuse_address = True
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == '__main__':
    main(sys.argv)