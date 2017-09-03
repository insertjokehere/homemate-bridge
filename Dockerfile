FROM python:3.6

WORKDIR /src

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . /src

RUN python setup.py install

ENTRYPOINT ["/src/bin/entrypoint.sh"]

VOLUME /config
