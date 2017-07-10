import socketserver
import json
import time
import struct
import binascii
import random
import string

import paho.mqtt.client as mqtt

from hexdump import hexdump

from hassdevice.devices import Switch

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

with open("orvibo.key", 'rb') as f:
    orvibo_key = f.read()

MAGIC = bytes([0x68, 0x64])
ID_UNSET = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Commands that the server sends, don't send an ACK when we see the switch ACK
CMD_SERVER_SENDS = [15]


class HomemateSwitch(Switch):

    def __init__(self, handler, *args, **kwargs):
        self._handler = handler
        super().__init__(*args, **kwargs)

    def on_state_change(self, new_state):
        self._handler.order_state_change(new_state == self.payload_on)


class HomematePacket:

    def __init__(self, data, keys):
        self.raw = data

        try:
            # Check the magic bytes
            self.magic = data[0:2]
            assert self.magic == MAGIC

            # Check the 'length' field
            self.length = struct.unpack(">H", data[2:4])[0]
            assert self.length == len(data)

            # Check the packet type
            self.packet_type = data[4:6]
            assert self.packet_type == bytes([0x70, 0x6b]) or \
                self.packet_type == bytes([0x64, 0x6b])

            # Check the CRC32
            self.crc = binascii.crc32(data[42:]) & 0xFFFFFFFF
            data_crc = struct.unpack(">I", data[6:10])[0]
            assert self.crc == data_crc
        except AssertionError:
            print("Bad packet:")
            hexdump(data)
            raise

        self.switch_id = data[10:42]

        self.json_payload = self.decrypt_payload(keys[self.packet_type[0]], data[42:])

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
        data = payload.encode('utf-8')

        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data)
        padded_data += padder.finalize()

        encryptor = Cipher(
            algorithms.AES(key),
            modes.ECB(),
            backend=default_backend()
        ).encryptor()

        encrypted_payload = encryptor.update(padded_data)
        return encrypted_payload

    @classmethod
    def build_packet(cls, packet_type, key, switch_id, payload):
        encrypted_payload = cls.encrypt_payload(key, json.dumps(payload))
        crc = struct.pack('>I', binascii.crc32(encrypted_payload) & 0xFFFFFFFF)
        length = struct.pack('>H', len(encrypted_payload) + len(MAGIC + packet_type + crc + switch_id) + 2)

        packet = MAGIC + length + packet_type + crc + switch_id + encrypted_payload
        return packet


class HomemateTCPHandler(socketserver.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    _broker = None

    def __init__(self, *args, **kwargs):
        self.switch_id = None
        self.keys = {
            0x70: orvibo_key,
        }

        self.softwareVersion = None
        self.hardwareVersion = None
        self.language = None
        self.modelId = None
        self._switch_on = None
        self.serial = 0
        self.uid = None

        self._mqtt_switch = None

        super().__init__(*args, **kwargs)

    @property
    def switch_on(self):
        return self._switch_on

    @switch_on.setter
    def switch_on(self, value):
        print("New switch state: {}".format(value))
        self._switch_on = value
        if self._mqtt_switch is not None:
            self._mqtt_switch.state = self._mqtt_switch.payload_on if value else self._mqtt_switch.payload_off

    def order_state_change(self, new_state):
        payload = {
            "userName": "noone@example.com",
            "uid": self.uid,
            "value1": 0 if self.switch_on else 1,
            "value2": 0,
            "value3": 0,
            "value4": 0,
            "defaultResponse": 1,
            "ver": "2.4.0",
            "qualityOfService": 1,
            "delayTime": 0,
            "cmd": 15,
            "deviceId": self.switch_id.decode("utf-8"),
            "clientSessionId": self.switch_id.decode("utf-8"),
            "order": 'on' if new_state else 'off',
            "serial": self.serial
        }

        self.serial += 1

        packet = HomematePacket.build_packet(
            packet_type=bytes([0x64, 0x6b]),
            key=self.keys[0x64],
            switch_id=self.switch_id,
            payload=payload
        )

        self.request.sendall(packet)

    def handle(self):
        # self.request is the TCP socket connected to the client
        print("Got connection from {}".format(self.client_address[0]))
        while True:
            data = self.request.recv(1024).strip()

            packet = HomematePacket(data, self.keys)

            print("Got payload: {}".format(packet.json_payload))

            # Handle the ID field
            if self.switch_id is None and packet.switch_id == ID_UNSET:
                # Generate a new ID
                print("Generating a new switch ID")
                self.switch_id = ''.join(
                    random.choice(
                        string.ascii_lowercase + string.digits
                    ) for _ in range(32)
                ).encode('utf-8')
            elif self.switch_id is None:
                # Switch has already been assigned an ID, save it
                print("Reusing existing ID")
                self.switch_id = packet.switch_id

            print("Switch ID: {}".format(packet.switch_id))

            assert 'cmd' in packet.json_payload
            assert 'serial' in packet.json_payload

            if packet.json_payload['cmd'] in self.cmd_handlers:
                response = self.cmd_handlers[packet.json_payload['cmd']](packet)
            elif packet.json_payload['cmd'] not in CMD_SERVER_SENDS:
                response = self.handle_default(packet)
            else:
                response = None

            if response is not None:
                response = self.format_response(packet, response)
                print("Sending response {}".format(response))
                response_packet = HomematePacket.build_packet(
                    packet_type=packet.packet_type,
                    key=self.keys[packet.packet_type[0]],
                    switch_id=self.switch_id,
                    payload=response
                )
                # Sanity check: Does our own packet look valid?
                #HomematePacket(response_packet, self.keys)
                self.request.sendall(response_packet)

            if packet.json_payload['cmd'] == 32:
                self.order_state_change(not self.switch_on)

    def format_response(self, packet, response_payload):
        response_payload['cmd'] = packet.json_payload['cmd']
        response_payload['serial'] = packet.json_payload['serial']
        response_payload['status'] = 0

        if 'uid' in packet.json_payload:
            response_payload['uid'] = packet.json_payload['uid']

        return response_payload

    def handle_hello(self, packet):
        for f in ['softwareVersion', 'hardwareVersion', 'language', 'modelId']:
            setattr(self, f, packet.json_payload[f])

        if 0x64 not in self.keys:
            key = ''.join(
                random.choice(
                    string.ascii_lowercase + string.ascii_uppercase + string.digits
                ) for _ in range(16)
            )
            self.keys[0x64] = key.encode('utf-8')
        else:
            key = self.keys[0x64].decode('utf-8')

        return {
            'key': key
        }

    def handle_default(self, packet):
        # If we don't recognise the packet, just send an "ACK"
        return {}

    def handle_heartbeat(self, packet):
        self.uid = packet.json_payload['uid']
        return {
            'utc': int(time.time())
        }

    def handle_state_update(self, packet):
        if packet.json_payload['statusType'] != 0:
            print("Got unknown statusType: {}".format(packet.json_payload))

        if packet.json_payload['value1'] == 0:
            self.switch_on = True
        else:
            self.switch_on = False

        return None  # No response to this packetnaughty_jones

    def handle_handshake(self, packet):
        self._mqtt_switch = HomemateSwitch(
            self,
            name="Homemate Switch",
            entity_id=packet.json_payload['uid']
        )

        self._mqtt_switch.connect(self.__class__._broker)

        return self.handle_default(packet)

    @property
    def cmd_handlers(self):
        return {
            0: self.handle_hello,
            32: self.handle_heartbeat,
            42: self.handle_state_update
        }

    @classmethod
    def set_broker(cls, broker):
        cls._broker = broker

if __name__ == "__main__":

    HOST, PORT = "0.0.0.0", 10001

    mqtt_client = mqtt.Client()
    mqtt_client.connect("localhost", 1883, 60)

    mqtt_client.loop_start()

    HomemateTCPHandler.set_broker(
        mqtt_client
    )

    # Create the server, binding to localhost on port 9999
    server = socketserver.TCPServer((HOST, PORT), HomemateTCPHandler)

    print(HOST, PORT)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    try:
        server.serve_forever()
    finally:
        mqtt_client.loop_stop()
