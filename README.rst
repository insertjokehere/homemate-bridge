========
Overview
========

.. start-badges

.. list-table::
    :stub-columns: 1

    * - docs
      - |docs|
    * - tests
      - | |travis| |requires|
        | |codecov|
    * - package
      - | |version| |wheel| |supported-versions| |supported-implementations|
        | |commits-since|

.. |docs| image:: https://readthedocs.org/projects/homemate-bridge/badge/?style=flat
    :target: https://readthedocs.org/projects/homemate-bridge
    :alt: Documentation Status

.. |travis| image:: https://travis-ci.org/insertjokehere/homemate-bridge.svg?branch=master
    :alt: Travis-CI Build Status
    :target: https://travis-ci.org/insertjokehere/homemate-bridge

.. |requires| image:: https://requires.io/github/insertjokehere/homemate-bridge/requirements.svg?branch=master
    :alt: Requirements Status
    :target: https://requires.io/github/insertjokehere/homemate-bridge/requirements/?branch=master

.. |codecov| image:: https://codecov.io/github/insertjokehere/homemate-bridge/coverage.svg?branch=master
    :alt: Coverage Status
    :target: https://codecov.io/github/insertjokehere/homemate-bridge

.. |version| image:: https://img.shields.io/pypi/v/homemate-bridge.svg
    :alt: PyPI Package latest release
    :target: https://pypi.python.org/pypi/homemate-bridge

.. |commits-since| image:: https://img.shields.io/github/commits-since/insertjokehere/homemate-bridge/v0.1.0.svg
    :alt: Commits since latest release
    :target: https://github.com/insertjokehere/homemate-bridge/compare/v0.1.0...master

.. |wheel| image:: https://img.shields.io/pypi/wheel/homemate-bridge.svg
    :alt: PyPI Wheel
    :target: https://pypi.python.org/pypi/homemate-bridge

.. |supported-versions| image:: https://img.shields.io/pypi/pyversions/homemate-bridge.svg
    :alt: Supported versions
    :target: https://pypi.python.org/pypi/homemate-bridge

.. |supported-implementations| image:: https://img.shields.io/pypi/implementation/homemate-bridge.svg
    :alt: Supported implementations
    :target: https://pypi.python.org/pypi/homemate-bridge


.. end-badges

Orvibo "Homemate" to MQTT bridge

* Free software: Apache Software License 2.0

Supported Devices
=================

* Orvibo S20c

If you've managed to the bridge working with other devices, please open an issue so I can update the list!

Requirements
============

* Python 3.x, on Linux
* The python3-dev, build-essential and libssl-dev packages (for Debian-based systems, or the equivelant)
* One or more supported switches
* HomeAssistant
* An MQTT broker connected to HomeAssistant

Installation
============

* Obtain the Orvibo 'PK' key (see below) as a `keys.json` file
* Redirect all traffic for homemate.orvibo.com, TCP port 10001 to the machine running the bridge. The easiest way to do this is to override the DNS record, but how you can do this will greatly depend on how your network is set up
* `Configure HomeAssistant <https://home-assistant.io/docs/mqtt/discovery/>_` to discover MQTT devices
* Install the bridge:
::

   pip install homemate-bridge

* Run the bridge:
::

   homemate-bridge --keys-file <path/to/key/file> --mqtt-host ...

* After ~30 seconds you should see devices connecting to the bridge, and new switch entities in HomeAssistant

Getting the Orvibo 'PK' encryption key
======================================

As part of the initial handshake with the server, the switch sends a 'hello' packet encrypted with a static key, and expects a packet encrypted with the same key in response that sets a different key for all subsequent packets. This is the 'PK' key, and is not included with the source code until I work out if there would be legal issues with doing so. Fortunately, Orvibo hardcode this key in the source code of the 'Kepler' Android app.

* Download the `Kepler apk <http://www.orvibo.com/software/android/kepler.apk>_`
* Run the `homemate-bridge-seed-keyfile --keys-file keys.json <path/to/apk>` script to extract the key and save it. Note that the file will be overwritten if it exists.

Documentation
=============

https://homemate-bridge.readthedocs.io/

Development
===========

To run the all tests run::

    tox
