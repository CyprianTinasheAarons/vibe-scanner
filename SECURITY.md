# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's security advisory
feature for this repository. Do not open a public issue containing an exploit,
credential, private URL, or sensitive scan output.

Include the affected version, reproduction steps, expected impact, and any
suggested mitigation. Reports will be acknowledged as soon as practical.

## Scanner scope

Vibe Scanner is a focused static and response-metadata scanner. A clean result
does not guarantee that an application is secure and does not replace a threat
model, penetration test, dependency audit, or architecture review.

Repository scans are read-only. URL scans make a public GET request chain and
reject localhost and private-network targets.
