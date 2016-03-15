FROM debian:jessie

RUN sed s:deb:deb-src: /etc/apt/sources.list >> /etc/apt/sources.list

RUN apt-get update && apt-get build-dep -y squid3 && apt-get install -y wget tar xz-utils libssl-dev

RUN mkdir /src \
    && cd /src \
    && wget http://www.squid-cache.org/Versions/v4/squid-4.0.7.tar.xz \
    && tar -xvvf squid-4.0.7.tar.xz
    
RUN cd /src/squid-4.0.7 && \
    ./configure \
        --datadir=/usr/share/squid3 \
		--sysconfdir=/etc/squid3 \
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
		--with-swapdir=/var/spool/squid3 \
		--with-logdir=/var/log/squid3 \
		--with-pidfile=/var/run/squid3.pid \
		--with-filedescriptors=65536 \
		--with-large-files \
		--with-default-user=proxy
		
ARG cores=1

RUN cd /src/squid-4.0.7 && \
    make -j$cores && \
    make install
