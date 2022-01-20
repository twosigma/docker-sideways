#!/bin/bash -x

SSL_DIR=/etc/squid/ssl

install -d -o root -g proxy -m 0755 "$SSL_DIR"

# This obviously won't verify successfully. This is just so we can do a POC
# with a self-signed cert and run the docker image standalone without errors.
cat > "$SSL_DIR/mitm.conf" << EOF
[ req ]
default_bits = 2048
prompt = no
encrypt_key = no
default_md = sha256
distinguished_name = dn
x509_extensions = x509_ext
[ dn ]
CN = sideways
emailAddress = sideways@sideways.local
O = Sideways
OU = Sideways
L = New York
ST = New York
C = US
[ x509_ext ]
subjectAltName = DNS:sideways.local
basicConstraints = CA:TRUE
EOF

openssl req -x509 -config "$SSL_DIR/mitm.conf" \
	-newkey rsa -keyout "$SSL_DIR/mitm_key.pem" \
	-out "$SSL_DIR/mitm_crt.pem"

if [ ! -z "$MITM_KEY" -a -r "$MITM_KEY" ]; then
	echo "Copying $MITM_KEY as MITM key..."
	install -o root -g proxy -m 0640 "$MITM_KEY" "$SSL_DIR/mitm_key.pem"
fi

if [ ! -z "$MITM_CERT" -a -r "$MITM_CERT" ]; then
	echo "Copying $MITM_CERT as MITM CA..."
	install -o root -g proxy -m 0644 "$MITM_CERT" "$SSL_DIR/mitm_crt.pem"
fi

# We can mount additional certs in /etc/ssl/extra_certs, which we
# can then add to our main CA path.
if [ -d /etc/ssl/extra_certs ]; then
	find /etc/ssl/extra_certs/ -name '*.pem' -exec cp {} /etc/ssl/certs/ \;
	/usr/bin/c_rehash /etc/ssl/certs
fi

chown proxy: /dev/stdout
chown proxy: /dev/stderr

# Initialize the certificates database
/usr/local/libexec/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB
chown -R proxy:proxy /var/spool/squid/ssl_db

mkdir -p /etc/squid/conf.d

# Deny all by default. This should be replaced at startup by Helm, for instance.
if [ ! -f /etc/squid/conf.d/acls.conf ]; then
	touch /etc/squid/conf.d/acls.conf
	cat << EOF > /etc/squid/conf.d/acls.conf
http_access deny all
EOF
fi

chown proxy:proxy /var/log/squid

# Run any hook script deployed for squid; hooks can keep running in the
# background and will be sent a SIGTERM when squid exits (see at the end of this
# startup script).
mkdir -p /etc/squid/hooks.d
for hook in $(find /etc/squid/hooks.d/ -type f -executable); do
	$hook &
done

# Create any required cache dirs
squid -z -N

# Start squid
squid -N 2>&1 &
PID=$!

# This construct allows signals to kill the container successfully.
jobs -l
children=$(echo `jobs -p`)
trap "kill -TERM $children" INT TERM

wait $PID
exit $?
