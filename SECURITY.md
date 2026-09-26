# Security

ArtifactDiff is a local-first prototype. The default workflow does not require a
network account or cloud service.

## Supported versions

Security fixes, if any, are considered only for the latest source on the default
branch while the project remains at `0.1.0` alpha. There is no published package
support channel yet.

## Reporting a vulnerability

Please open a private GitHub security advisory on this repository, or contact the
maintainer through the GitHub profile linked from the repository owner account.
Do not file a public issue for unfixed vulnerabilities.

## Scope notes

- Private keys and customer contracts must stay on the operator machine.
- Synthetic Golden Path demos use ephemeral test keys and must not be reused as
  production trust material.
- MCP and review-desk paths are designed to avoid returning full contracts, page
  images, or key material to model or browser contexts; treat misconfiguration as
  a local security issue.
