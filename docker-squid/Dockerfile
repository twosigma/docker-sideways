FROM debian:jessie

RUN sed s:deb:deb-src: /etc/apt/sources.list >> /etc/apt/sources.list

RUN apt-get update && apt-get build-dep -y squid3 && apt-get install -y wget tar xz-utils libssl-dev

RUN mkdir /src \
    && cd /src \
    && wget http://www.squid-cache.org/Versions/v4/squid-4.0.7.tar.xz \
    && tar -xvvf squid-4.0.7.tar.xz
    
RUN cd /src/squid-4.0.7 && \
    ./configure \
        --prefix=/usr \
        --datadir=/usr/share/squid4 \
		--sysconfdir=/etc/squid4 \
		--localstatedir=/var \
		--mandir=/usr/share/man \
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
		--with-swapdir=/var/spool/squid4 \
		--with-logdir=/var/log/squid4 \
		--with-pidfile=/var/run/squid4.pid \
		--with-filedescriptors=65536 \
		--with-large-files \
		--with-default-user=proxy
		
ARG CONCURRENCY=1

RUN cd /src/squid-4.0.7 && \
    make -j$CONCURRENCY && \
    make install

# Download p2cli dependency
RUN wget -O /usr/local/bin/p2 \
    https://github.com/wrouesnel/p2cli/releases/download/r1/p2 && \
    chmod +x /usr/local/bin/p2

# Clone and build proxychains-ng for SSL upstream proxying
ARG PROXYCHAINS_COMMITTISH=aea917265349880f6cc5dffc9d4afa61227fd330

RUN apt-get install -y git

RUN git clone https://github.com/rofl0r/proxychains-ng.git /src/proxychains-ng && \
    cd /src/proxychains-ng && \
    git checkout $PROXYCHAINS_COMMITTISH && \
    ./configure --prefix=/usr --sysconfdir=/etc && \
    make -j$CONCURRENCY && make install

COPY squid.conf.p2 /squid.conf.p2
COPY squid.bsh /squid.bsh

# Configuration environment
ENV HTTP_PORT=3128 ICP_PORT= HTCP_PORT= MITM_PROXY= MITM_CERT= MITM_KEY=  VISIBLE_HOSTNAME=docker-squid4 MAX_CACHE_SIZE=40000 MAX_OBJECT_SIZE="1536 MB" MEM_CACHE_SIZE="128 MB"

EXPOSE 3128

CMD /squid.bsh
