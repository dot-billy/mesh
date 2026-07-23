# Security policy

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability.

Use GitHub's **Security** tab and private vulnerability reporting for this
repository. Include the affected component, reproduction steps, realistic
impact, and any suggested mitigation. Do not include production credentials,
private keys, customer data, or unrelated infrastructure details.

The maintainers will acknowledge reports and coordinate validation and
disclosure on a best-effort basis. There is currently no paid bug-bounty
program.

## Supported versions

Mesh is a working lifecycle foundation and does not yet publish a stable
supported release line. Security fixes target the latest `main` revision unless
a release advisory states otherwise.

Review the [threat model](docs/threat-model.md), [production hardening guide](docs/production-hardening.md),
and platform-specific security boundaries before deployment.
