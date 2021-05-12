#!/bin/bash -x

SSL_DIR=/etc/squid/ssl

install -d -o root -g proxy -m 0755 "$SSL_DIR"

# This obviously won't verify successfully. This is
# just so we can do a POC with a self-signed cert.
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
emailAddress = re-proxy-support@twosigma.com
O = Two Sigma Investments, LP
OU = Two Sigma Investments, LP
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

chown proxy: /dev/stdout
chown proxy: /dev/stderr

# Initialize the certificates database
/usr/local/libexec/security_file_certgen -c -s /var/spool/squid/ssl_db -M 4MB
chown -R proxy:proxy /var/spool/squid/ssl_db

mkdir -p /etc/squid/conf.d

# Only grant debug tools access by default. This will be replaced
# by helm at startup.
if [ ! -f /etc/squid/conf.d/acls.conf ]; then
	touch /etc/squid/conf.d/acls.conf
	cat << EOF > /etc/squid/conf.d/acls.conf
acl me src 127.0.0.1/32
acl CONNECT method CONNECT
acl debugtools dstdomain localhost
acl debugtools_port port 8081

http_access allow all CONNECT debugtools debugtools_port
http_access allow all !debugtools
http_access deny all
EOF
fi

chown proxy:proxy /var/log/squid

if [ ! -z "$KEYTAB_SVC_URL" ]; then
	export KRB5_KTNAME=/var/spool/keytabs/proxy
	mkdir -p /var/spool/keytabs
	touch $KRB5_KTNAME
	chown proxy $KRB5_KTNAME
	chmod 400 $KRB5_KTNAME

	while true; do
		date >> /var/log/keytab_refresh.log
		token=$(curl -s 'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=iam.twosigma.com&format=full' 2>> $ktlog)
		echo "Token: $token" >> $ktlog
		kt=$(mktemp -t keytab.XXXXXX)
		ktlog=/var/log/keytab_refresh.log
		curl -v -s -o $kt -H "Authorization: Bearer $token" \
			"$KEYTAB_SVC_URL" >> $ktlog 2>&1
		if [ $? -ne 0 ]; then
			rm $kt
			sleep 60
			continue
		fi
		cat $kt | jq -r .keytab | base64 -d > \
			$KRB5_KTNAME 2>> $ktlog
		if [ $? -ne 0 ]; then
			echo "** curl result **" >> $ktlog
			cat $kt >> $ktlog
			echo "** end curl result **" >> $ktlog
			rm $kt
			sleep 60
			continue
		fi
		rm $kt
		sleep 14400
	done &
fi

mkdir /var/log/tcpdump

python3 /debugtools.py 2>&1 &

# Create any required cache dirs
squid -z -N

# Start squid normally
squid -N 2>&1 &
PID=$!

# This construct allows signals to kill the container successfully.
children=$(echo `jobs -p`)
trap "kill -TERM $children" INT TERM

wait $PID
exit $?
