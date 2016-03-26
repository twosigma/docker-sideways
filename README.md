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
    
