# Squid4 with SSL proxying

This dockerfile builds a Squid 4.0.7 instance and includes all the necessary
tooling to run it as a MITM (man-in-the-middle) SSL proxy.

There's a number of reasons to do this - the big one being optimizing caching
and delivery of objects during docker builds which might be downloading them
from SSL protected endpoints.

It will require you to generate your own CA and set it as trusted.

The resulting docker image uses the following configuration environment
variables:

 * `HTTP_PORT`
    Default: `3128`
 * `ICP_PORT`
    If set, enables ICP on the given port for all users.
 * `HTCP_PORT`
    If set, enables HTCP on the given port for all users.
 * `MITM_PROXY`
    If set, tries to enable MITM SSL proxy functionality (requires CERT and KEY)
 * `MITM_CERT`
    If set, the given PEM certificate is copied and used as the CA authority for 
    MITM'ing connections.
 *  `MITM_KEY`
    If set, the given PEM certificate is copied and used as the signing key for 
    the MITM CA.
 * `VISIBLE_HOSTNAME`
    Default: `docker-squid4`
    Should be set to a unique value if you are chaining multiple proxy servers.
 * `MAX_CACHE_SIZE`
    Default: `40000`
    Cache size in megabytes. The cache defaults to `/var/cache/squid4`. You 
    should mount a volume here to make it persistent.
 * `MAX_OBJECT_SIZE`
    Default `"1536 MB"`
    Maximum object size to store in the cache. This is set high as one of my
    typical use cases is proxying distribution images.
 * `MEM_CACHE_SIZE`
    Default: `"128 MB"`
    Default memory cache size. I've no real clue what this should be, but RAM
    is plentiful so I like to keep it fairly large.
    
# Example Usage
The following command line will get you up and running quickly. It presumes
you've generated a suitable CA certificate and are intending to use the proxy
as a local MITM on your machine:
```
sudo mkdir -p /srv/squid/cache
docker run -it -p 3128:127.0.0.1:3128 --rm \
    -v /srv/squid/cache:/var/cache/squid4 \
    -v /etc/ssl/certs:/etc/ssl/certs:ro \ 
    -v /etc/ssl/private/local_mitm.pem:/local-mitm.pem:ro \
    -v /etc/ssl/certs/local_mitm.pem:/local-mitm.crt:ro \
    -e MITM_CERT=/local-mitm.crt \
    -e MITM_KEY=/local-mitm.pem \
    -e MITM_PROXY=yes \
    squid
```

Note that it doesn't really matter where we mount the certificate - the image
launch script makes a copy as root to avoid messing with permissions anyway.

## Unit File for systemd
This is an example of a systemd unit file to persistly start squid4:
```
[Unit]
Description=Squid4 Docker Container
Documentation=http://wiki.squid.org
After=network.target docker.service
Requires=docker.service

[Service]
ExecStartPre=-/usr/bin/docker kill squid4
ExecStartPre=-/usr/bin/docker rm squid4
ExecStart=/usr/bin/docker run --net=host --rm \
    -v /srv/squid/cache:/var/cache/squid4 \
    -v /etc/ssl/certs:/etc/ssl/certs:ro \
    -v /etc/ssl/private/local_mitm.pem:/local_mitm.pem:ro \
    -v /etc/ssl/certs/local_mitm.pem:/local_mitm.crt:ro \
    -e MITM_KEY=/local_mitm.pem \
    -e MITM_CERT=/local_mitm.crt \
    -e MITM_PROXY=yes \
    --name squid4 \
    squid

[Install]
WantedBy=multi-user.target
```
