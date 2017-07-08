import socketserver
import json

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

with open("orvibo.key", 'rb') as f:
    orvibo_key = f.read()

MAGIC = bytes([0x68, 0x64])
ID_UNSET = bytes([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
])

# Commands that the server sends, don't send ACKs when we see the response
CMD_SERVER_SENDS = [15]


class HomematePacket:

    def __init__(self, data, keys):
        self.raw = data

        # Check the magic bytes
        self.magic = data[0:2]
        assert self.magic == MAGIC

        # Check the 'length' field
        self.length = struct.unpack(">H", data[2:4])[0]
        assert self.length == len(data)

        # Check the packet type
        self.packet_type = data[4:6]
        assert self.packet_type == [0x70, 0x6b] or self.packet_type == [0x64, 0x6b]

        # Check the CRC32
        self.crc = binascii.crc32(data[42:]) & 0xFFFFFFFF
        self.crc = "{0:#0{1}x}".format(crc, 10)
        data_crc = '0x' + binascii.hexlify(data[6:10]).decode('utf-8')
        assert self.crc == data_crc

        self.switch_id = data[10:42]

        self.json_payload = self.decrypt_payload(keys[packet_type[0]], data[42:])

    def decrypt_payload(self, key, encrypted_payload):
        decryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).decryptor()

        data = decryptor.update(encrypted_payload)

        unpadder = padding.PKCS7(128).unpadder()
        unpad = unpadder.update(data)
        unpad += unpadder.finalize()

        # sometimes payload has an extra trailing null
        if unpad[-1] == 0x00:
            unpad = unpad[:-1]
        return json.loads(unpad.decode('utf-8'))

    @classmethod
    def encrypt_payload(self, key, payload):
        data = json.dumps(payload).encode('utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).encryptor()

        encrypted_payload = encryptor.update(data)
        return encrypted_payload

    @classmethod
    def build_packet(cls, packet_type, key, switch_id, payload):
        encrypted_payload = cls.encrypt_payload(key, payload)
        crc = struct.pack('>I', binascii.crc32(encrypted_payload) & 0xFFFFFFFF)
        length = struct.pack('>H', len(encrypted_payload))

        return MAGIC + length + packet_type + crc + switch_id + encrypted_payload


class HomemateTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, *args, **kwargs):
        self.switch_id = None
        self.keys = {
            0x70: orvibo_key
        }

        self.cmd_handlers = {
            0: self.handle_hello
        }

    def handle(self):
        # self.request is the TCP socket connected to the client
        print("Got connection from {}".format(self.client_address[0]))
        while True:
            data = self.request.recv(1024).strip()

            packet = HomematePacket(data, self.keys)

            # Handle the ID field
            if self.switch_id is None and packet.switch_id == ID_UNSET:
                # Generate a new ID
                self.switch_id = []  #TODO generate ID
            elif self.switch_id is None:
                # Switch has already been assigned an ID, save it
                self.switch_id = packet.switch_id

            assert 'cmd' in packet_data
            assert 'serial' in packet_data

            if packet_data['cmd'] in self.cmd_handlers:
                response = self.cmd_handlers[packet_data['cmd']](packet_data)
            elif packet_data['cmd'] not in CMD_SERVER_SENDS:
                response = self.handle_default(packet_data)
            else:
                response = None

            if response is not None:
                self.request.send_all(HomematePacket.build_packet(
                    packet_type=packet.packet_type,
                    key=self.keys[packet.packet_type[0]],
                    switch_id=self.switch_id,
                    payload=response
                ))

if __name__ == "__main__":

    HOST, PORT = "0.0.0.0", 10001

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), MyTCPHandler)

    print(HOST, PORT)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()
