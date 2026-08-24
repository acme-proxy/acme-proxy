# Custom Plugins Examples

This section provides complete examples of custom plugin scripts that can be
integrated into `acme-proxy`. These scripts must be marked as executable (`chmod
+x`).

## Custom signer script

A custom signer that passes the CSR to a fictional internal API to obtain a
certificate.

```bash
#!/bin/bash
# /etc/acme-proxy/signer/internal-pki.sh
set -e

# We only handle the "issue" hook in this example
if [ "$ACME_SIGNER_HOOK" = "issue" ]; then
    # Read the JSON payload from stdin
    PAYLOAD=$(cat)

    # Extract the base64 encoded CSR
    CSR_B64=$(echo "$PAYLOAD" | jq -r '.csr_der_base64')

    # Call internal PKI API
    # The API is expected to return a JSON with a 'certificate_pem' field.
    RESPONSE=$(curl -s -X POST https://pki.internal.company.com/api/sign \
        -H "Content-Type: application/json" \
        -d "{\"csr\": \"$CSR_B64\", \"order_id\": \"$ACME_SIGNER_ORDER_ID\"}")

    # Extract PEM from response
    PEM=$(echo "$RESPONSE" | jq -r '.certificate_pem')

    if [ -n "$PEM" ] && [ "$PEM" != "null" ]; then
        # Output the PEM chain to stdout (leaf first, then issuers)
        echo "$PEM"
        exit 0
    else
        # Exit 1 (any non-zero other than 3) = internal failure -> the client
        # gets a 500 and the order is marked invalid.
        #
        # Exit 3 is RESERVED for "this CSR is bad" -> the client gets a 400
        # badCSR and the order stays "ready" so it can retry with a corrected
        # CSR. Only use 3 when the PKI rejected the CSR itself, never for an
        # API outage like this one.
        echo "internal PKI API did not return a certificate" >&2
        exit 1
    fi
fi

# Hooks this example does not implement. `revoke` must succeed or the proxy
# leaves the order un-revoked, so returning non-zero here would be wrong for a
# real deployment;
# implement it, or set supports_crl/supports_renewal_info = false (the default)
# so those hooks are never invoked at all.
exit 1
```

## Custom filter script

A custom filter that checks the client IP against a threat intelligence feed
before allowing the connection.

```bash
#!/bin/bash
# /etc/acme-proxy/filters/threat-intel.sh

if [ "$ACME_FILTER_HOOK" = "connection" ]; then
    # Skip checking local IPs
    if [[ "$ACME_FILTER_CLIENT_IP" == 10.* ]] || [[ "$ACME_FILTER_CLIENT_IP" == 192.168.* ]]; then
        exit 0
    fi

    # Query threat intel API
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" "https://threat.internal/api/check?ip=$ACME_FILTER_CLIENT_IP")

    if [ "$STATUS" = "200" ]; then
        # IP is clean
        exit 0
    else
        # IP is flagged, deny the request
        echo "Client IP $ACME_FILTER_CLIENT_IP is flagged in Threat Intel"
        exit 1
    fi
fi

exit 0
```

## Custom IPAM script

A custom IPAM backend that reads the permitted names for an address out of a
CSV the estate already maintains, one `address,name,name,...` row per machine.

```bash
#!/bin/bash
# /etc/acme-proxy/ipam/lookup.sh
set -u

INVENTORY="/etc/acme-proxy/ipam/inventory.csv"

# The address arrives twice — in the environment and in the JSON on stdin.
# This script uses the environment, so it never has to read stdin at all; a
# script that exits without reading it is fine and is not an error.
ROW=$(grep -m1 "^${ACME_IPAM_CLIENT_IP}," "$INVENTORY")

if [ -z "$ROW" ]; then
    # 3 is RESERVED: "this inventory holds no record of that address". The
    # `ipam` check words its own refusal for it, distinct from the one below.
    exit 3
fi

# Exit 0 with the permitted names, one per line. They are lowercased and
# stripped of a trailing dot for you, so print whatever form the file holds.
# Printing nothing here would mean "recorded, and entitled to nothing" — a
# different answer from exit 3, and also a refusal.
echo "$ROW" | cut -d, -f2- | tr ',' '\n'
exit 0
```

> Every **other** non-zero exit — a missing inventory file, a `grep` that could
> not run, a timeout — is reported as a retryable `500`, never as a denial. That
> is deliberate: an inventory this server cannot reach has decided nothing, so
> issuance stops rather than failing open. Do not use a non-zero exit to refuse
> a client; refuse by not printing the name.

> `acme-proxy filter explain` really runs the policy, so it executes this
> script too.

## Custom notification script

A custom notification script that sends a Slack message when a certificate is
revoked.

```bash
#!/bin/bash
# /etc/acme-proxy/notify/slack.sh

WEBHOOK_URL="https://hooks.slack.com/services/AAAAAAAAA/BBBBBBBBB/XXXXXXXXXXXXXXXXXXXXXXXX"

# The JSON payload is always on stdin; read it before anything else. For
# certificate_revoked it carries the reason code, which has no env var.
PAYLOAD=$(cat)

if [ "$ACME_NOTIFY_HOOK" = "certificate_revoked" ]; then
    # ACME_NOTIFY_IDENTIFIERS is only populated for certificate_issued, so it
    # would render empty here — take the order id from the environment and the
    # reason from the payload instead.
    REASON=$(echo "$PAYLOAD" | jq -r '.reason // "unspecified"')
    MESSAGE="🚨 Certificate Revoked! Serial: \`$ACME_NOTIFY_CERT_SERIAL\` | Order: \`$ACME_NOTIFY_ORDER_ID\` | Reason: \`$REASON\`"

    curl -s -X POST -H 'Content-type: application/json' \
        --data "{\"text\": \"$MESSAGE\"}" \
        "$WEBHOOK_URL"
fi

exit 0
```

> A notification script's exit code is only logged — it can never fail the ACME
> request that triggered it.
