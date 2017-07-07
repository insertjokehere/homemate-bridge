### Research into interfacing with Orvibo "Homemate" devices

#### stream_decode.py

A tool to decrypt JSON payloads from Wireshark packet captures of Homemate devices

* Needs python3, install requirements from requirements.txt
* Capture packets with Wireshark, right click, Follow -> TCP stream. Select "YAML" for "show data as", save file
* Run `python3 stream_decode.py [file]`
* You will need to extract the Orvibo secret key from the "Kepler" Android app, and write it to a file called `orvibo.key`. 16 alphanumerics.
* There is an example stream file included
