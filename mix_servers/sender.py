from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.serialization import load_pem_public_key
import sys
import base64
import socket
import time
import threading


class Server:
    def __init__(self, index, ip, port):
        self.ip = ip
        self.ip_bytes = socket.inet_aton(ip)
        self.port = int(port)
        self.port_bytes = self.port.to_bytes(2, byteorder='big')
        self.pk = load_pk(index)

    def send(self, msg):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((self.ip, self.port))
            s.sendall(msg)


class Message:
    def __init__(self, words):
        self.text = words[0].encode()
        self.path = words[1].split(',')
        self.round = int(words[2])
        self.password = words[3].encode()
        self.salt = words[4].encode()
        self.ip = words[5]
        self.ip_bytes = socket.inet_aton(self.ip)
        self.port = int(words[6])
        self.port_bytes = self.port.to_bytes(2, byteorder='big')

    def __repr__(self):
        return f'{self.round} {self.text} {self.path} {self.ip} {self.port}'


def load_servers():
    servers = []
    with open('ips.txt', 'r') as f:
        index = 1
        for line in f.readlines():
            words = line.split(' ')
            servers.append(Server(index, words[0], words[1]))
            index += 1
    return servers


def load_pk(index):
    with open(f'pk{index}.pem', 'rb') as f:
        return load_pem_public_key(
            data=f.read(),
            backend=None
        )


def parse_messages(index):
    messages = []
    with open(f'messages{index}.txt', 'r') as f:
        lines = f.readlines()
        for line in lines:
            words = line.split(' ')
            messages.append(Message(words))
    # messages.sort(key=lambda message: message.round)
    return messages


def create_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)


def encrypt_pk(pk, msg):
    return pk.encrypt(
        msg,
        padding=padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def build_message(servers, message):
    # initialize msg
    key = create_key(message.password, message.salt)
    c = key.encrypt(message.text)
    msg = message.ip_bytes + message.port_bytes + c

    prev_server_ip_bytes = None
    prev_server_port_bytes = None
    path = list(map(lambda x: int(x) - 1, message.path))[::-1]
    for server_index in path:
        server = servers[server_index]
        # prepend the previous server's ip and port (if exists)
        if prev_server_ip_bytes is not None and prev_server_port_bytes is not None:
            msg = prev_server_ip_bytes + prev_server_port_bytes + msg
        msg = encrypt_pk(server.pk, msg)
        prev_server_ip_bytes = server.ip_bytes
        prev_server_port_bytes = server.port_bytes
    # return the server that we should send the message to
    return servers[int(message.path[0]) - 1], msg


def wait_until_first_message():
    time.sleep(2)


def send_round(servers, messages):
    for message in messages:
        server, msg_data = build_message(servers, message)
        server.send(msg_data)


def set_all_round_timers(servers, messages):
    timers = []
    round_duration = 60
    rounds = set([m.round for m in messages])
    for msg_round in rounds:
        curr_messages = [m for m in messages if m.round == msg_round]
        t = threading.Timer(
            interval=msg_round * round_duration,
            function=send_round,
            args=[servers, curr_messages]
        )
        timers.append(t)
        t.start()
    return timers


def wait_for_all_timers(timers):
    for timer in timers:
        timer.join()


def main():
    if len(sys.argv) < 2:
        # missing messages index argument
        return

    # wait a few seconds to make sure we send all messages in the correct round
    wait_until_first_message()

    servers = load_servers()
    messages = parse_messages(sys.argv[1])

    wait_until_first_message()
    timers = set_all_round_timers(servers, messages)
    wait_for_all_timers(timers)


if __name__ == '__main__':
    main()
