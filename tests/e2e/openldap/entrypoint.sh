#!/bin/sh
# Loads the seed into an empty database, then runs slapd in the foreground.
# `-d 256` (stats) is what prints "slapd starting", the lab's readiness gate.
set -e
mkdir -p /run/lab-slapd /var/lib/lab-ldap
slapadd -f /etc/ldap/lab-slapd.conf -l /seed.ldif
exec slapd -d 256 -f /etc/ldap/lab-slapd.conf -h "ldap:/// ldaps:///"
