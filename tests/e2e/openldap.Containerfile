# The directory the web admin's LDAP realms and Dex (the OpenID Connect
# provider of `admin_sso.rs`) both sign people in against: OpenLDAP with a
# fixed seed of people and `groupOfNames` groups. The TLS key and certificate
# are not baked in -- each lab generates its own for the container's name and
# copies them to /certs before the container starts.
#
# Debian's `slapd` package configures a database of its own on install; it is
# ignored, since the entrypoint runs `slapd -f` on the `slapd.conf` copied here.
FROM debian:trixie-slim
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends slapd ldap-utils \
    && rm -rf /var/lib/apt/lists/*
COPY openldap/slapd.conf /etc/ldap/lab-slapd.conf
COPY openldap/seed.ldif /seed.ldif
COPY openldap/entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
