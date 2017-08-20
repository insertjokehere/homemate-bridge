from homemate_bridge.cli import HomematePacket

import json
import sys
import base64


def __main__():
    with open(sys.argv[1]) as f:
        log = json.load(f)
        for entry in log:
            keys = {int(k): base64.b64decode(v) for k, v in entry['keys'].items()}
            data = base64.b64decode(entry['data'])
            packet = HomematePacket(data, keys)
            print("{} {} {}".format(
                entry['client'],
                'sends' if entry['direction'] == 'in' else 'recieves',
                packet.json_payload
            ))


__main__()
