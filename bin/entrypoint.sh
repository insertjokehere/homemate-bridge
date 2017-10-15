#!/bin/bash -x

if [ ! -f /config/keys.json ]; then
    echo "/config/keys.json not found, attempting to populate..."
    curl -s -o /tmp/kepler.apk http://www.orvibo.com/software/android/kepler.apk
    cd /tmp
    sha256sum -c /src/known_apks.sha256 || echo "kepler.apk is not one of the known APKs, next step may fail! Please open a Github issue!"
    cd /src
    homemate-bridge-seed-keyfile --keys-file /config/keys.json /tmp/kepler.apk
fi

homemate-bridge --keys-file /config/keys.json --devices-file /config/devices.json $@
