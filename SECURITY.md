# Security policy

MaldocTrace parses hostile files by design, so bugs in its parsers and emulator are security bugs: a crash, hang, excessive memory use or path traversal triggered by a crafted document can be used to blind a triage pipeline or to attack the machine that runs it.

## Supported versions

Security fixes go into the latest release. Please check that a problem still happens with the latest version (or `main`) before reporting it.

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the [Security tab](https://github.com/debugactiveprocess/MaldocTrace/security) of the repository and choose **Report a vulnerability**. Do not open a public issue for them.

Useful details:

- the MaldocTrace version (`maldoctrace version`) and platform;
- the command line you used;
- a minimal input that triggers the problem. If it is a live malware sample, send its SHA-256 (and where it can be obtained, such as MalwareBazaar) rather than the file, or attach it in a password-protected archive (password `infected`).

You should get a first answer within a week. Once a fix is released, the advisory is published with credit to the reporter, unless you prefer to stay anonymous.

## Scope

In scope: crashes, hangs, unbounded resource use, files written outside the `--dump-payloads` directory, and any way a sample could get MaldocTrace to execute code or contact the network. MaldocTrace never runs the sample and never makes network requests; anything that breaks either rule is a vulnerability.

Out of scope: samples that MaldocTrace fails to detect or misclassifies. Please report those as regular issues, ideally with a SHA-256.

## Verifying releases

Each release lists SHA-256 checksums in `checksums.txt`, and every archive carries a GitHub build provenance attestation. To check that an archive was built by this repository's release workflow:

```bash
gh attestation verify maldocTrace_<version>_linux_amd64.tar.gz --repo debugactiveprocess/MaldocTrace
```
