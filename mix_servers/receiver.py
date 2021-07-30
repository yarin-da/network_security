from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import sys
import socket
import datetime
import threading


# receive all data, until there's none
# it's useful because only one message is sent per connection
def recv_all(sock):
    buffer_size = 1024
    msg = bytes()
    while True:
        # read into an arbitrary sized buffer
        read_bytes = sock.recv(buffer_size)
        if not read_bytes:
            break
        # append to the data read so far
        msg += read_bytes
    return msg


def get_timestamp():
    return datetime.datetime.now().strftime("%H:%M:%S")


def handle_client(sock, key):
    with sock:
        # receive a whole message
        data = recv_all(sock)
        if data:
            message = key.decrypt(data).decode()
            curr_time = get_timestamp()
            print(f'{message} {curr_time}')


def main_loop(sock, key):
    while True:
        conn, addr = sock.accept()
        # handle client in a new thread, so we can listen to clients simultaneously
        threading.Thread(target=handle_client(conn, key)).start()


def listen_for_senders(host, port, key):
    # initialize socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        main_loop(s, key)


# create key using password and salt (as seen in the documentation)
def create_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return Fernet(key)


def main():
    if len(sys.argv) < 4:
        # missing password and salt arguments
        return
    password = sys.argv[1].encode()
    salt = sys.argv[2].encode()
    if not sys.argv[3].isdigit():
        # wrong argument type --- port must be an integer
        return
    port = int(sys.argv[3])
    key = create_key(password, salt)
    # listen for senders from ANY IP
    listen_for_senders('0.0.0.0', port, key)


if __name__ == '__main__':
    main()
