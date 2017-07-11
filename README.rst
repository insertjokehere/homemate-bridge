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

.. |commits-since| image:: https://img.shields.io/github/commits-since/insertjokehere/homemate-bridge/v0.0.1.svg
    :alt: Commits since latest release
    :target: https://github.com/insertjokehere/homemate-bridge/compare/v0.0.1...master

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

Installation
============

::

    pip install homemate-bridge

Documentation
=============

https://homemate-bridge.readthedocs.io/

Development
===========

To run the all tests run::

    tox

Note, to combine the coverage data from all the tox environments run:

.. list-table::
    :widths: 10 90
    :stub-columns: 1

    - - Windows
      - ::

            set PYTEST_ADDOPTS=--cov-append
            tox

    - - Other
      - ::

            PYTEST_ADDOPTS=--cov-append tox
