FROM debian:buster

ENV SQUID_VERSION=4.14

# Normalize apt sources
RUN cat /etc/apt/sources.list | grep -v '^#' | sed /^$/d | sort | uniq > sources.tmp.1 && \
	cat /etc/apt/sources.list | sed s/deb\ /deb-src\ /g | grep -v '^#' | sed /^$/d | sort | uniq > sources.tmp.2 && \
	cat sources.tmp.1 sources.tmp.2 > /etc/apt/sources.list && \
	rm -f sources.tmp.1 sources.tmp.2

RUN apt-get update && \
	DEBIAN_FRONTEND=noninteractive apt-get build-dep -y squid && \
	DEBIAN_FRONTEND=noninteractive apt-get -y install \
		curl gnupg iproute2 jq krb5-user \
		libssl-dev nghttp2-proxy net-tools openssl procps \
		python3 python3-gssapi \
		python3-kerberos strace tar tcpdump vim

ADD http://www.squid-cache.org/Versions/v4/squid-$SQUID_VERSION.tar.gz /usr/local/src/
ADD http://www.squid-cache.org/Versions/v4/squid-$SQUID_VERSION.tar.gz.asc /usr/local/src/

COPY squid.asc /usr/local/src/squid.asc
RUN gpg --import /usr/local/src/squid.asc && \
	gpg --verify /usr/local/src/squid-$SQUID_VERSION.tar.gz.asc \
		/usr/local/src/squid-$SQUID_VERSION.tar.gz

RUN mkdir /usr/local/src/squid && \
	tar -C /usr/local/src/squid --strip-components=1 -zxvf /usr/local/src/squid-$SQUID_VERSION.tar.gz

RUN cd /usr/local/src/squid && \
	./configure \
	--prefix=/usr/local \
	--datadir=/usr/local/share/squid \
	--sysconfdir=/etc/squid \
	--localstatedir=/var \
	--mandir=/usr/share/man \
	--enable-http-violations \
	--enable-inline \
	--enable-async-io=8 \
	--enable-storeio="ufs,aufs,diskd,rock" \
	--enable-removal-policies="lru,heap" \
	--enable-delay-pools \
	--enable-cache-digests \
	--enable-underscores \
	--enable-icap-client \
	--enable-follow-x-forwarded-for \
	--enable-auth-basic="DB,fake,getpwnam,LDAP,NCSA,NIS,PAM,POP3,RADIUS,SASL,SMB" \
	--enable-auth-digest="file,LDAP" \
	--enable-auth-negotiate="kerberos,wrapper" \
	--enable-auth-ntlm="fake" \
	--enable-external-acl-helpers="file_userip,kerberos_ldap_group,LDAP_group,session,SQL_session,unix_group,wbinfo_group" \
	--enable-url-rewrite-helpers="fake" \
	--enable-eui \
	--enable-esi \
	--enable-icmp \
	--enable-zph-qos \
	--with-openssl \
	--enable-ssl \
	--enable-ssl-crtd \
	--disable-translation \
	--with-swapdir=/var/spool/squid \
	--with-logdir=/var/log/squid \
	--with-pidfile=/var/run/squid.pid \
	--with-filedescriptors=65536 \
	--with-large-files \
	--with-default-user=proxy \
	--disable-arch-native

RUN cd /usr/local/src/squid && \
    make && \
    make install

COPY squid.sh /squid.sh
COPY squid.conf /etc/squid/squid.conf
COPY debugtools.py /debugtools.py

EXPOSE 3128

ENTRYPOINT ["/squid.sh"]
