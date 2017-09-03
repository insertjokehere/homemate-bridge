import socketserver
import json
import time
import struct
import binascii
import random
import string
import logging
import sys
import argparse
import base64
import os

import paho.mqtt.client as mqtt

from hexdump import hexdump

from hassdevice.devices import Switch
from hassdevice.hosts import SimpleMQTTHost

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
from cryptography.hazmat.primitives import padding

logger = logging.getLogger(__name__)

MAGIC = bytes([0x68, 0x64])
ID_UNSET = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

# Commands that the server sends, don't send an ACK when we see the switch ACK
CMD_SERVER_SENDS = [15]


class HomemateSwitch(Switch):

    def __init__(self, handler, *args, **kwargs):
        self._handler = handler
        super().__init__(*args, **kwargs)

    def on_state_change(self, new_state):
        logger.debug("Setting new state: {}".format(new_state))
        self._handler.order_state_change(new_state == self.payload_on)


class PacketLog:

    log = []
    logfile = None

    OUT = "out"
    IN = "in"

    @classmethod
    def enable(cls, logfile):
        cls.logfile = logfile

    @classmethod
    def record(cls, data, direction, keys=None, client=None):
        if cls.logfile is not None:
            cls.log.append({
                'data': base64.b64encode(data).decode('utf-8'),
                'direction': direction,
                'keys': {
                    k: base64.b64encode(v).decode('utf-8') for k, v in keys.items()
                },
                'client': client
            })

            with open(cls.logfile, 'w') as f:
                json.dump(cls.log, f)


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
            logger.error("Bad packet:")
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
    _initial_keys = {}
    _device_settings = {}

    def __init__(self, *args, **kwargs):
        logger.debug("New handler")
        self.switch_id = None
        self.keys = dict(self.__class__._initial_keys.items())

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
        logger.debug("New switch state: {}".format(value))
        self._switch_on = value
        if self._mqtt_switch is not None:
            self._mqtt_switch.state = self._mqtt_switch.payload_on if value else self._mqtt_switch.payload_off

    def order_state_change(self, new_state):
        if self._switch_on is None:
            return

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

        PacketLog.record(packet, PacketLog.OUT, self.keys, self.client_address[0])

        logger.debug("Sending state change for {}, new state {}".format(self.switch_id, new_state))
        logger.debug("Payload: {}".format(payload))

        self.request.sendall(packet)

    def handle(self):
        # self.request is the TCP socket connected to the client
        logger.debug("Got connection from {}".format(self.client_address[0]))

        self.settings = self.__class__._device_settings.get(self.client_address[0], {})
        if 'name' not in self.settings:
            self.settings['name'] = "Homemate Switch " + self.client_address[0]

        logger.debug("Device settings: {}".format(self.settings))

        while True:
            data = self.request.recv(1024).strip()

            PacketLog.record(data, PacketLog.IN, self.keys, self.client_address[0])

            packet = HomematePacket(data, self.keys)

            logger.debug("{} sent payload: {}".format(self.switch_id, packet.json_payload))

            # Handle the ID field
            if self.switch_id is None and packet.switch_id == ID_UNSET:
                # Generate a new ID
                logger.debug("Generating a new switch ID")
                self.switch_id = ''.join(
                    random.choice(
                        string.ascii_lowercase + string.digits
                    ) for _ in range(32)
                ).encode('utf-8')
            elif self.switch_id is None:
                # Switch has already been assigned an ID, save it
                logger.debug("Reusing existing ID")
                self.switch_id = packet.switch_id

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
                logger.debug("Sending response {}".format(response))
                response_packet = HomematePacket.build_packet(
                    packet_type=packet.packet_type,
                    key=self.keys[packet.packet_type[0]],
                    switch_id=self.switch_id,
                    payload=response
                )

                PacketLog.record(response_packet, PacketLog.OUT, self.keys, self.client_address[0])

                # Sanity check: Does our own packet look valid?
                #HomematePacket(response_packet, self.keys)
                self.request.sendall(response_packet)

            if self._mqtt_switch is None and packet.json_payload['cmd'] == 32:
                # Setup the mqtt connection once we see the initial state update
                # Otherwise, we will get the previous state too early
                # and the switch will disconnect when we try to update it
                self._mqtt_switch = HomemateSwitch(
                    self,
                    name=self.settings['name'],
                    entity_id=self.client_address[0].replace('.', '_')
                )

                self.__class__._broker.add_device(self._mqtt_switch)

    def format_response(self, packet, response_payload):
        response_payload['cmd'] = packet.json_payload['cmd']
        response_payload['serial'] = packet.json_payload['serial']
        response_payload['status'] = 0

        if 'uid' in packet.json_payload:
            response_payload['uid'] = packet.json_payload['uid']

        return response_payload

    def handle_hello(self, packet):
        for f in ['softwareVersion', 'hardwareVersion', 'language', 'modelId']:
            setattr(self, f, packet.json_payload.get(f, None))

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
            logger.warning("Got unknown statusType: {}".format(packet.json_payload))

        if packet.json_payload['value1'] == 0:
            self.switch_on = True
        else:
            self.switch_on = False

        return None  # No response to this packet

    def handle_handshake(self, packet):

        return self.handle_default(packet)

    @property
    def cmd_handlers(self):
        return {
            0: self.handle_hello,
            32: self.handle_heartbeat,
            42: self.handle_state_update,
            6: self.handle_handshake
        }

    @classmethod
    def set_broker(cls, broker):
        cls._broker = broker

    @classmethod
    def add_key(cls, key_id, key):
        cls._initial_keys[key_id] = key

    @classmethod
    def set_device_settings(cls, settings):
        cls._device_settings = settings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--homemate-port", type=int, default=10001)
    parser.add_argument("--homemate-interface", default="0.0.0.0")
    parser.add_argument("--keys-file", default=None, required=False)
    parser.add_argument("--devices-file", default=None, required=False)
    parser.add_argument("--packet-log-file", default=None, required=False, help="Log packets to file")
    SimpleMQTTHost.add_argparse_params(parser)
    args = parser.parse_args()

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG, format="%(asctime)s - %(message)s")

    if args.keys_file is not None:
        with open(args.keys_file, 'r') as f:
            keys = json.load(f)
            for k, v in keys.items():
                HomemateTCPHandler.add_key(int(k), base64.b64decode(v))
    else:
        logger.warning("Keys file not configured, connections will probably fail!")

    if args.devices_file is not None and os.path.exists(args.devices_file):
        with open(args.devices_file, 'r') as f:
            HomemateTCPHandler.set_device_settings(json.load(f))

    if args.packet_log_file is not None:
        PacketLog.enable(args.packet_log_file)

    host = SimpleMQTTHost()
    host.configure_from_docker_secrets()
    host.configure_from_env()
    host.configure_from_args(args)

    host.start(block=False)

    HomemateTCPHandler.set_broker(
        host
    )

    logger.debug("Listening on {}, port {}".format(args.homemate_interface, args.homemate_port))

    server = socketserver.ThreadingTCPServer((args.homemate_interface, args.homemate_port), HomemateTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    try:
        server.serve_forever()
    finally:
        host.stop()
