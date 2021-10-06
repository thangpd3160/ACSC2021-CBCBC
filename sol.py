import socket
from base64 import b64decode, b64encode

def recvuntil(clientSocket, string):
    output = b'' 
    while True:
        output += clientSocket.recv(8092).rstrip()       
        if string in output:
            return output

def register(clientSock):
    clientSock.sendall(b'1\n')
    output = recvuntil(clientSock, b'Your username:')
    clientSock.sendall(b'\n')
    output = recvuntil(clientSock, b'>')
    token = output.split(b'\n')[0][len('Your token:'):]
    return token

def login(clientSock, username, token):
    clientSock.sendall(b'2\n')
    output = recvuntil(clientSock, b'Your username:')
    clientSock.sendall(username + b'\n')
    output = recvuntil(clientSock, b'Your token:')
    clientSock.sendall(token + b'\n')
    output = recvuntil(clientSock, b'>')
    return output

def paddingOrarcleAttack(clientSock, token):
    token = b64decode(token)
    assert len(token) % 16 == 0
    
    iv1 = token[:16]
    iv2 = token[16:32]
    chunks = [token[i:i+16] for i in range(32, len(token), 16)]
    #padding orarcle attack
    #1st block
    #P1' + IV1' = IV1 + P1
    #C1' --> tC
    #IV' --> tIV
    #send IV1'IV2C'
    P1 = []
    pads = []
    for r in range(16):
        padValue = r + 1
        for ivValue in range(256):
            tIV = bytes([0]*(15-r) + [ivValue] + pads)
            tC = chunks[0]
            token = tIV + iv2 + tC
            token = b64encode(token)
            output = login(clientSock, b'', token)
            if b"Failed to login! Check your token again" not in output:
                Pk = ivValue ^ iv1[15-r] ^ padValue
                P1.append(Pk)
                # print('[+] Found c: ', chr(Pk))

                pads = []
                for padIndex in range(r + 1):
                    pads.append((padValue + 1) ^ P1[padIndex] ^ iv1[15 - padIndex])
                pads = pads[::-1]
                break
    
    #2nd block
    #P2' + IV2' = IV2 + P2
    #C1' --> tC
    #IV' --> tIV
    #send IV1IV2'C'
    P2 = []
    pads = []
    for r in range(16):
        padValue = r + 1
        for ivValue in range(256):
            tIV = bytes([0]*(15-r) + [ivValue] + pads)
            tC = chunks[0] + chunks[1]
            token = iv1 + tIV + tC
            token = b64encode(token)
            output = login(clientSock, b'', token)
            if b"Failed to login! Check your token again" not in output:
                Pk = ivValue ^ iv2[15-r] ^ padValue
                P2.append(Pk)
                # print('[+] Found c: ', chr(Pk))

                pads = []
                for padIndex in range(r + 1):
                    pads.append((padValue + 1) ^ P2[padIndex] ^ iv2[15 - padIndex])
                pads = pads[::-1]
                break
    P = "".join([chr(c) for c in P1[::-1]]) + "".join([chr(c) for c in P2[::-1]])
    username = P[:P.index(",")][len("{'username': '"):-1]
    return username
def getFlag(clientSock, username, token):
    login(clientSock, username, token)
    clientSock.sendall(b'1\n')
    output = recvuntil(clientSock, b'ACSC')
    return output

def main():
    host, port = 'localhost', 8000
    clientSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    clientSock.connect((host, port))
    
    output = recvuntil(clientSock, b'>')
    token = register(clientSock)

    username = paddingOrarcleAttack(clientSock, token)
    flag = getFlag(clientSock, username.encode(), token)
    print(flag.decode())
    

if __name__ == "__main__":
    main()