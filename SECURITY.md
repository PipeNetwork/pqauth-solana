# Security Policy

PQAuth is experimental and unaudited. Do not place production funds under this code.

Report vulnerabilities privately to the repository maintainers. Include the affected commit, reproducible steps, impact, and any suggested mitigation. Do not publish an exploit against a live deployment before maintainers and operators have a reasonable opportunity to disable or migrate it.

The following are explicitly in scope:

- signature or digest substitution;
- replay or sequence bypass;
- PDA/account substitution;
- CPI signer escalation;
- post-seal Ed25519 authority restoration;
- key-lineage rollback;
- malformed ML-DSA input causing excessive compute or panic;
- upgrade/immutability mismatches;
- rent or account-closing theft.
