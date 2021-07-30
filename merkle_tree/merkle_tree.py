from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64
import hashlib
import math


# RSA related functions

# generate private and public keys
def keygen():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # encode the key in PEM format
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # encode the key in PEM format
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # return the bytes to the caller
    return private_pem, public_pem


# sign the provided text with the provided key
def sign(key_lines, text):
    # parse lines into one string
    # as if all data has been read directly from the file
    data = '\n'.join(key_lines)
    key = load_pem_private_key(
        data=data.encode(),
        password=None,
        backend=default_backend()
    )
    key_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    input_signature = key.sign(
        data=text.encode(),
        padding=key_padding,
        algorithm=hashes.SHA256()
    )
    # encode the signature bytes in base64 format
    return base64.b64encode(input_signature)


def confirm_signature(key_lines, input_signature, confirm_text):
    # parse lines into one string
    # as if all data has been read directly from the file
    data = '\n'.join(key_lines)
    confirm_key = load_pem_public_key(
        data=data.encode(),
        backend=None
    )
    key_padding = padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    )
    try:
        # verify throws InvalidSignature exception when the verification has failed
        # thus, we'll return False if it's thrown
        confirm_key.verify(
            signature=base64.b64decode(input_signature.encode()),
            data=confirm_text.encode(),
            padding=key_padding,
            algorithm=hashes.SHA256()
        )
    except InvalidSignature:
        return False
    return True


# create a node with no children
def create_leaf(plaintext, parent=None):
    encoded = plaintext.encode()
    digest = hashlib.sha256(encoded).hexdigest()
    return Node(digest, None, None, parent)


# create a node with left and right as children
def create_father(left, right, parent=None):
    # concat the digests of left and right and hash the result
    encoded = f'{left.digest}{right.digest}'.encode()
    digest = hashlib.sha256(encoded).hexdigest()
    node = Node(digest, left, right, parent)
    left.parent = right.parent = node
    return node


# turn a digest argument into a binary string of length 256
def get_path(input_digest):
    return bin(int(input_digest, 16))[2:].zfill(256)


# check if the sha256(plaintext) is inside the tree
# this function acts independently of a tree object
# and works solely with the provided proof
def merkle_check_proof(plaintext, proof):
    root_digest = proof.split(' ')[0]
    digests = proof.split(' ')[1:]
    # calc sha256(plaintext)
    curr_digest = hashlib.sha256(plaintext.encode()).hexdigest()
    for item in digests:
        # the first character tells us in which direction we concatenate the digests
        direction = item[0]
        digest = item[1:]
        if direction == '0':
            concat = f'{digest}{curr_digest}'
        else:
            concat = f'{curr_digest}{digest}'
        curr_digest = hashlib.sha256(concat.encode()).hexdigest()
    # if sha256(plaintext) is inside the tree, then curr_digest must equal to the root
    return curr_digest == root_digest


class Node:
    def __init__(self, digest, left, right, parent=None):
        self.digest = digest
        self.left = left
        self.right = right
        self.parent = parent

    def is_leaf(self):
        return self.left is None and self.right is None


class MerkleTree:
    def __init__(self):
        # empty tree - no root and no leaves
        self.leaves = []
        self.root = None

    def add(self, plaintext):
        leaf = create_leaf(plaintext)
        self.leaves.append(leaf)

    def build(self):
        self.root = self.build_tree(self.leaves)
        if self.root is None:
            return ''
        return self.root.digest

    # this function builds a tree
    # in the simple case when the number of leaves is a power of 2
    # i.e. a full tree 
    def build_full_tree(self, leaves):
        num_of_leaves = len(leaves)
        if num_of_leaves == 1:
            return leaves[0]
        # each child contains exactly half of the leaves
        half = math.floor(num_of_leaves / 2)
        left = self.build_full_tree(leaves[:half])
        right = self.build_full_tree(leaves[half:])
        return create_father(left, right)

    def build_tree(self, leaves):
        num_of_leaves = len(leaves)
        if num_of_leaves == 0:
            return None
        if num_of_leaves == 1:
            return leaves[0]
        # this works because a power of 2 has exactly one bit on
        is_power_of_2 = (num_of_leaves & (num_of_leaves - 1) == 0)
        if is_power_of_2:
            return self.build_full_tree(leaves)
        # otherwise, find the largest power of 2 that is smaller than num_of_leaves
        log_val = math.floor(math.log2(num_of_leaves))
        power_of_2 = math.floor(math.pow(2, log_val))
        # the left child will be a full tree with power_of_2 children (more than half)
        left = self.build_full_tree(leaves[:power_of_2])
        # right child will contain the rest
        right = self.build_tree(leaves[power_of_2:])
        return create_father(left, right)

    def get_proof(self, index):
        proof = ''
        # if index is out of bounds
        if int(index) >= len(self.leaves):
            return proof
        # move from the leaf to the root (using the parent field inside node)
        node = self.leaves[int(index)]
        while node.parent is not None:
            prev = node
            node = node.parent
            # check from which side prev is connected to node (i.e. the parent)
            # and concat the relevant information accordingly
            # i.e. write his brother's digest and direction
            if node.left == prev:
                proof += f' 1{node.right.digest}'
            else:
                proof += f' 0{node.left.digest}'
        # precede the proof with the root's digest
        return f'{self.root.digest}{proof}'


class SparseTree:
    def __init__(self):
        # initialize a cache with the values of zero-nodes in all depths
        # i.e. root to leaf
        curr_digest = '0'
        self.zero_cache = [curr_digest]
        for i in range(256):
            concat = f'{curr_digest}{curr_digest}'.encode()
            curr_digest = hashlib.sha256(concat).hexdigest()
            self.zero_cache.insert(0, curr_digest)
        # we can simply set the root to a zero-node for now
        self.root = Node(self.zero_cache[0], None, None)

    def add(self, input_digest):
        # convert the digest to a binary string
        # which we will use to navigate through the tree
        path = get_path(input_digest)
        curr = self.root
        depth = 0
        for direction in path:
            # if we reached a leaf - it's turned into a father of two zero-node children
            if curr.is_leaf():
                child_digest = self.zero_cache[depth + 1]
                curr.left = Node(child_digest, None, None)
                curr.right = Node(child_digest, None, None)
            # navigate according to path
            if direction == '0':
                curr = curr.left
            else:
                curr = curr.right
            depth += 1
        # set the new added leaf's digest to 1
        curr.digest = '1'

    # recalculate the hashes all of the nodes
    def recalc_digests(self, node):
        if not node.is_leaf():
            # concatenate the children's hashes and hash the result
            left_digest = self.recalc_digests(node.left)
            right_digest = self.recalc_digests(node.right)
            concat = f'{left_digest}{right_digest}'.encode()
            node.digest = hashlib.sha256(concat).hexdigest()
        return node.digest

    # build the B part of the proof
    def build_proof_path(self, path, curr):
        if len(path) == 0:
            return ''
        if curr.is_leaf():
            return f' {curr.digest}'
        # move according to path and take the brother's digest everytime
        direction = path[0]
        if direction == '0':
            proof = f'{self.build_proof_path(path[1:], curr.left)} {curr.right.digest}'
        else:
            proof = f'{self.build_proof_path(path[1:], curr.right)} {curr.left.digest}'
        return proof

    # get the full proof of the provided digest (i.e. the whole A B)
    def get_proof(self, input_digest):
        path = get_path(input_digest)
        return f'{self.root.digest}{self.build_proof_path(path, self.root)}'

    # proofs might not contain the full path (because of zero-nodes) in the A part
    # thus, we'll fill the A part with the rest of the zero-nodes
    def parse_proof(self, proof):
        proof_words = proof.split(' ')
        num_of_digests = len(proof_words)
        root_digest = proof_words[0]
        digests = proof_words[1:]
        # the first digest might be the first zero-node that the provider stumbled upon
        # thus, we'll get rid of it because it's not relevant to the proof checking
        if digests[0] == self.zero_cache[num_of_digests - 2]:
            digests = digests[1:]
            num_of_digests -= 1
        # prepend zero-node of depth i to the list
        for i in range(num_of_digests, 257):
            digests.insert(0, self.zero_cache[i])
        return root_digest, digests

    # check if digest exists or does not exist according to the proof
    # this method can act independently of the tree object
    # it only uses the zero-cache that the tree provides but it can be calculated outside
    def check_proof(self, digest, val, proof):
        path = get_path(digest)[::-1]
        root_digest, digests = self.parse_proof(proof)
        curr_digest = val
        for i in range(256):
            direction = path[i]
            if direction == '0':
                concat = f'{curr_digest}{digests[i]}'
            else:
                concat = f'{digests[i]}{curr_digest}'
            curr_digest = hashlib.sha256(concat.encode()).hexdigest()
        return curr_digest == root_digest


def main():
    # create new trees to work with
    merkle_tree = MerkleTree()
    sparse_tree = SparseTree()
    # take input from the user indefinitely
    # make very simple argument checking and call the appropriate methods
    while True:
        user_input = input()
        if len(user_input) == 0:
            continue
        args = user_input.strip().split(' ', 1)
        cmd = args[0]
        if cmd == '1':
            if len(args) < 2:
                continue
            merkle_tree.add(args[1])
        elif cmd == '2':
            print(merkle_tree.build())
        elif cmd == '3':
            if len(args) < 2:
                continue
            print(merkle_tree.get_proof(args[1]))
        elif cmd == '4':
            args = args[1].split(' ', 1)
            if len(args) < 2:
                continue
            print(merkle_check_proof(args[0], args[1]))
        elif cmd == '5':
            private_pem, public_pem = keygen()
            print(private_pem.decode())
            # TODO: blank line?
            print(public_pem.decode())
        elif cmd == '6':
            if len(args) < 2:
                continue
            key_lines = []
            curr = args[1]
            # the key cosists of multiple line
            while len(curr) > 0:
                key_lines.append(curr)
                curr = input()
            print(sign(key_lines, merkle_tree.root.digest).decode())
        elif cmd == '7':
            key_lines = []
            curr = args[1]
            # the key cosists of multiple line
            while len(curr) > 0:
                key_lines.append(curr)
                curr = input()
            rest_of_args = input().split(' ')
            print(confirm_signature(key_lines, rest_of_args[0], rest_of_args[1]))
        elif cmd == '8':
            if len(args) < 2:
                continue
            sparse_tree.add(args[1])
        elif cmd == '9':
            if user_input != '9':
                continue
            print(sparse_tree.recalc_digests(sparse_tree.root))
        elif cmd == '10':
            if len(args) < 2:
                continue
            print(sparse_tree.get_proof(args[1]))
        elif cmd == '11':
            args = args[1].split(' ', 2)
            if len(args) < 3:
                continue
            print(sparse_tree.check_proof(args[0], args[1], args[2]))


if __name__ == '__main__':
    main()
