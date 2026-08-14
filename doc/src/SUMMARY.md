# Summary

- [Introduction](introduction.md)
  - [Core Concepts & Glossary](core/concepts.md)

# Getting Started
- [Quick Start](getting_started/quick_start.md)
- [Installation](getting_started/installation.md)
- [Trusting the CA](getting_started/trusting_the_ca.md)
- [Deployment](getting_started/deployment.md)
  - [TLS Termination](features/tls_termination.md)

# Core Components
- [Profiles & Routing](core/profiles.md)
- [Signers](signers/index.md)
  - [Local CA](signers/local_ca.md)
    - [Hardware Keys (PKCS#11)](signers/local_ca_hsm.md)
  - [Relay](signers/relay.md)
  - [Custom Script](signers/custom.md)
- [Challenge Validation](challenges/index.md)
  - [HTTP-01](challenges/http_01.md)
  - [DNS-01](challenges/dns_01.md)
  - [TLS-ALPN-01](challenges/tls_alpn_01.md)
- [Filters & Policies](filters/index.md)
  - [Policy: rules and conditions](filters/policy.md)
  - [Checks](filters/checks.md)
  - [Allowed IP](filters/allowed_ip.md)
  - [Path](filters/path.md)
  - [Reverse DNS](filters/reverse_dns.md)
  - [Identifiers](filters/identifiers.md)
  - [EAB](filters/eab.md)
  - [Custom Script](filters/custom.md)
- [IPAM](ipam/index.md)
  - [NetBox](ipam/netbox.md)
  - [phpIPAM](ipam/phpipam.md)

# Configuration
- [Configuration Reference](configuration/reference.md)
- [Common Scenarios](configuration/scenarios.md)

# ACME Protocol
- [Protocol Support](features/index.md)
  - [External Account Binding (EAB)](features/eab.md)
  - [Key Rollover](features/key_change.md)
  - [Renewal Information (ARI)](features/renewal_info.md)

# Operations
- [Admin CLI](operations/cli.md)
- [Web Admin](operations/webadmin.md)
  - [Users & Sessions](operations/webadmin_users.md)
  - [Customizing the Panel](operations/webadmin_templates.md)
- [Revocation & CRL](operations/revocation.md)
- [Notifications](notifications/index.md)
  - [Custom Templates](notifications/templates.md)
  - [Email](notifications/email.md)
  - [Mattermost](notifications/mattermost.md)
  - [Custom WebHook](notifications/custom.md)
- [Audit Trail](operations/audit.md)
- [Monitoring & Observability](operations/monitoring.md)
- [Maintenance & Troubleshooting](operations/troubleshooting.md)

# Security
- [Security Model](security/index.md)
- [Hardening Checklist](security/hardening.md)

# Developer Documentation
- [Architecture & Design](dev/architecture.md)
- [Database Schema](dev/database.md)
- [Custom Plugins Examples](dev/custom_plugins.md)
- [Testing & Coverage](dev/testing.md)
- [Contributing](dev/contributing.md)
