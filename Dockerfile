FROM python:3.6

WORKDIR /src

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY . /src

RUN python setup.py install

ENV TINI_VERSION v0.16.1
ADD https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini /tini
RUN chmod +x /tini
ENTRYPOINT ["/tini", "--"]

CMD ["/src/bin/entrypoint.sh"]

VOLUME /config
