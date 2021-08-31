FROM debian:buster

ENV GOPATH=/usr/local/src/go

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get -y install \
		git golang openssl procps vim

COPY httpmirror.go /usr/local/src/httpmirror.go
RUN cd /usr/local/src && \
	go build httpmirror.go && \
	install -o root -g root -m 0755 httpmirror /usr/local/bin/httpmirror

RUN mkdir /etc/httpmirror && \
	cd /etc/httpmirror && \
	openssl req -x509 -newkey rsa:2048 -nodes \
	-days 3650 -keyout key.pem -out crt.pem \
	-subj '/C=US/ST=New York/CN=httpmirror' && \
	chgrp www-data /etc/httpmirror/*.pem && \
	chmod 640 /etc/httpmirror/*.pem

USER www-data

EXPOSE 8080/tcp
EXPOSE 8443/tcp

ENTRYPOINT ["/usr/local/bin/httpmirror", \
	"-key", "/etc/httpmirror/key.pem", \
	"-crt", "/etc/httpmirror/crt.pem" ]
