# Security Policy

## Supported versions

Security fixes are applied to the latest release and the current default branch unless otherwise stated.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability that could put users at risk before a fix is available.

Use GitHub's private vulnerability reporting for this repository when available. Include:

- affected version or commit
- impact and attack prerequisites
- reproduction steps or a proof of concept
- suggested mitigation, if known

Avoid including real credentials, private DNS data, internal addresses, or other sensitive information in reports.

## Security-sensitive areas

DnsForward handles network traffic and can be exposed on privileged DNS ports. Changes involving upstream TLS verification, client access control, request limits, remote rule fetching, listener defaults, or metrics exposure should be reviewed with security impact in mind.
