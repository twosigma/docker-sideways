#!/bin/bash

# Setup the ssl_cert directory
if [ ! -d /etc/squid4/ssl_cert ]; then
    mkdir /etc/squid4/ssl_cert
fi

chown -R proxy:proxy /etc/squid4
chmod 700 /etc/squid4/ssl_cert

# Setup the squid cache directory
if [ ! -d /var/cache/squid4 ]; then
    mkdir -p /var/cache/squid4
fi
chown -R proxy: /var/cache/squid4
chmod -R 750 /var/cache/squid4

if [ ! -z $MITM_PROXY ]; then
    if [ ! -z $MITM_KEY ]; then
        echo "Copying $MITM_KEY as MITM key..."
        cp $MITM_KEY /etc/squid4/ssl_cert/mitm.pem
        chown root:proxy /etc/squid4/ssl_cert/mitm.pem
    fi

    if [ ! -z $MITM_CERT ]; then
        echo "Copying $MITM_CERT as MITM CA..."
        cp $MITM_CERT /etc/squid4/ssl_cert/mitm.crt
        chown root:proxy /etc/squid4/ssl_cert/mitm.crt
    fi

    if [ -z $MITM_CERT ] || [ -z $MITM_KEY ]; then
        echo "Must specify $MITM_CERT AND $MITM_KEY." 1>&2
        exit 1
    fi
fi

chown proxy: /dev/stdout
chown proxy: /dev/stderr

# Initialize the certificates database
/usr/libexec/security_file_certgen -c -s /var/spool/squid4/ssl_db
chown -R proxy: /var/spool/squid4/ssl_db

#ssl_crtd -c -s
#ssl_db

# Set the configuration
if [ "$CONFIG_DISABLE" != "yes" ]; then
    p2 -t /squid.conf.p2 > /etc/squid4/squid.conf

    # Parse the cache peer lines from the environment and add them to the
    # configuration
    echo '# CACHE PEERS FROM DOCKER' >> /etc/squid4/squid.conf
    env | grep 'CACHE_PEER' | sort | while read cacheline; do
        echo "# $cacheline " >> /etc/squid4/squid.conf
        line=$(echo $cacheline | cut -d'=' -f2-)
        echo "cache_peer $line" >> /etc/squid4/squid.conf
    done

    # Parse the extra config lines and append them to the configuration
    echo '# EXTRA CONFIG FROM DOCKER' >> /etc/squid4/squid.conf
    env | grep 'EXTRA_CONFIG' | sort | while read extraline; do
        echo "# $extraline " >> /etc/squid4/squid.conf
        line=$(echo $extraline | cut -d'=' -f2-)
        echo "$line" >> /etc/squid4/squid.conf
    done
else
    echo "/etc/squid4/squid.conf: CONFIGURATION TEMPLATING IS DISABLED."
fi

if [ ! -e /etc/squid4/squid.conf ]; then
    echo "ERROR: /etc/squid4/squid.conf does not exist. Squid will not work."
    exit 1
fi

# If proxychains is requested and config templating is active
if [ "$PROXYCHAIN" = "yes" ] && [ "$CONFIG_DISABLE" != "yes" ]; then
    echo "# PROXYCHAIN CONFIG FROM DOCKER" > /etc/proxychains.conf
    # Enable remote DNS proxy
    if [ ! -z "$PROXYCHAIN_DNS" ]; then
        echo "proxy_dns" >> /etc/proxychains.conf
    fi
    # Configure proxy type
    if [ ! -z "$PROXYCHAIN_TYPE" ]; then
        echo "$PROXYCHAIN_TYPE" >> /etc/proxychains.conf
    else
        echo "strict_chain" >> /etc/proxychains.conf
    fi
    
    echo "[ProxyList]" >> /etc/proxychains.conf
    env | grep 'PROXYCHAIN_PROXY' | sort | while read proxyline; do
        echo "# $proxyline " >> /etc/squid4/squid.conf
        line=$(echo $proxyline | cut -d'=' -f2-)
        echo "$line" >> /etc/proxychains.conf
    done
else
    echo "/etc/proxychains.conf : CONFIGURATION TEMPLATING IS DISABLED"
fi

# Build the configuration directories if needed
squid -z -N

if [ "$PROXYCHAIN" = "yes" ]; then
    if [ ! -e /etc/proxychains.conf ]; then
        echo "ERROR: /etc/proxychains.conf does not exist. Squid with proxychains will not work."
        exit 1
    fi 
    # Start squid with proxychains
    exec proxychains4 squid -N
else
    # Start squid normally
    exec squid -N
fi
