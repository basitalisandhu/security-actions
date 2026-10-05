# Security policy

## Scope

This repository contains GitHub composite actions and the scripts they run inside other people's CI. Security-relevant problems here are:

- A script that executes untrusted input (file contents, sitemap XML, SBOM JSON, API responses) in a way that lets a repository or a remote server run code on the runner.
- A script that leaks a token or a matched secret: into logs, the job summary, SARIF, a pull request comment or a request to a third party.
- A workflow or action that asks for more permissions than it needs, or lets an unpinned third-party action run.
- A detector that misses a pattern it claims to find (false negative) or reports safe text (false positive) in a way that could mislead a review.
- Fixtures that contain real credentials. Fixtures must only contain synthetic values.

## Reporting

Please report vulnerabilities privately through GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). If that is not available, open an issue titled "Security contact request" without details and a maintainer will reply with a private channel.

You can expect an acknowledgement within 72 hours and a fix or a public statement within 14 days for confirmed issues. Credit is given in the release notes unless you prefer otherwise.

## Supported versions

The latest `v0.x.y` release (and therefore the `v0` tag) and the `main` branch receive fixes.

## Safe use of these actions

- Pin to an immutable tag (`@v0.1.0`) or a commit SHA when you need reproducible runs; `@v0` follows the latest release.
- Grant only the permissions each action lists in its README. `security-events: write` is needed only while `upload-sarif` is `"true"`; `pull-requests: write` only for sbom-diff-comment.
- The scripts make no network calls except the ones the action exists to make: indexnow-ping talks to the sitemap host and the IndexNow endpoint, sbom-diff-comment to the GitHub API, llms-txt-check to the site URL when one is given and to linked pages when `check-links` is on.
- Scanner output is redacted, but the SARIF file and the job summary still name the file and line of each finding. Treat them as sensitive until the credential has been rotated.
- A clean scan is not proof of safety. The detectors are pattern-based and cover the formats listed in each README.
