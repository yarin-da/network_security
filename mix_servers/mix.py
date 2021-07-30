import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import sys
import socket
import threading


# this class contains all information related to a message
class Message:
    def __init__(self, ip, port, text):
        self.ip = ip
        self.port = port
        self.text = text


class MessageDatabase:
    def __init__(self):
        self.messages = []
        # use a lock so only one thread can read/write
        self.lock = threading.Lock()

    def add(self, message):
        with self.lock:
            self.messages.append(message)

    # empty the message list, and return all messages
    def consume_messages(self):
        with self.lock:
            ret = self.messages
            self.messages = []
            return ret


def read_sk(index):
    # read the secret key (according to the argument)
    with open(f'sk{index}.pem', 'rb') as f:
        key = load_pem_private_key(
            data=f.read(),
            password=None,
            backend=default_backend(),
        )
        return key


def decrypt_msg(sk, cipher):
    return sk.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def parse_message(msg_data, sk):
    decrypted = decrypt_msg(sk, msg_data)
    # decrypted = IP (4 bytes) || PORT (2 bytes) || CIPHER
    ip_bytes = decrypted[:4]
    port_bytes = decrypted[4:6]
    text = decrypted[6:]

    # parse data
    ip = socket.inet_ntoa(ip_bytes)
    port = int.from_bytes(port_bytes, byteorder='big')
    return Message(ip, port, text)


# receive all data, until there's none
# it's useful because only one message is sent per connection
def recv_all(sock):
    msg = bytes()
    while True:
        read_bytes = sock.recv(1024)
        if not read_bytes:
            break
        msg += read_bytes
    return msg


def handle_client(sock, sk, message_db):
    with sock:
        # receive a whole message
        data = recv_all(sock)
        if data:
            message = parse_message(data, sk)
            message_db.add(message)


def main_loop(sock, sk, message_db):
    while True:
        conn, addr = sock.accept()
        # handle client in a new thread, so we can listen to clients simultaneously
        threading.Thread(target=handle_client(conn, sk, message_db)).start()


def listen_for_clients(host, port, sk, message_db):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # initialize socket
        s.bind((host, port))
        s.listen()
        main_loop(s, sk, message_db)


def send_message(message):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((message.ip, message.port))
        s.sendall(message.text)


def get_socket_info(index):
    with open('ips.txt') as f:
        # fetch the line that is relevant to this server
        line = f.readlines()[index - 1]
        host, port = line.split(' ')
        return host, int(port)


def set_next_round_timer(message_db):
    round_duration = 60
    t = threading.Timer(
        interval=round_duration,
        function=consume_messages,
        args=[message_db]
    )
    t.start()


def consume_messages(message_db):
    # make sure this function is called again in the next round
    set_next_round_timer(message_db)
    # send all messages that were aggregated so far
    messages = message_db.consume_messages()
    # send them in a random order (unrelated to receive order)
    random.shuffle(messages)
    for message in messages:
        send_message(message)


def main():
    if len(sys.argv) < 2:
        # missing private key file argument
        return
    if not sys.argv[1].isdigit():
        # wrong argument type --- index must be an integer
        return
    index = int(sys.argv[1])
    # get this server's address and port
    host, port = get_socket_info(index)
    sk = read_sk(index)
    message_db = MessageDatabase()

    set_next_round_timer(message_db)
    listen_for_clients(host, port, sk, message_db)


if __name__ == '__main__':
    main()
