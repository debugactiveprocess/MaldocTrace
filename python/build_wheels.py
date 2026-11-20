"""Build platform wheels that ship the MaldocTrace release binaries.

Usage:
    python python/build_wheels.py --version 0.6.0 --dist dist --out wheels

``--dist`` holds the release archives produced by the release workflow
(maldocTrace_<version>_<goos>_<goarch>.zip / .tar.gz). For each one a wheel
is written to ``--out``; the binary is installed as the ``maldoctrace``
command and the ``maldoctrace`` Python package wraps it. Only the standard
library is used.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import io
import os
import tarfile
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
NAME = "maldoctrace"

# goos/goarch -> wheel platform tags. The binaries are static (CGO_ENABLED=0),
# so one Linux build serves both glibc and musl systems. Go 1.23 needs macOS 11.
PLATFORMS = {
    ("windows", "amd64"): ["win_amd64"],
    ("windows", "arm64"): ["win_arm64"],
    ("linux", "amd64"): ["manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_1_x86_64"],
    ("linux", "arm64"): ["manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_1_aarch64"],
    ("darwin", "amd64"): ["macosx_11_0_x86_64"],
    ("darwin", "arm64"): ["macosx_11_0_arm64"],
}

SUMMARY = (
    "Analyzer for malicious Office, RTF and OneNote documents that emulates "
    "macros and scripts to recover the commands they would run, without executing them"
)
KEYWORDS = "malware-analysis,maldoc,vba,onenote,dfir,incident-response,ioc"
CLASSIFIERS = [
    "Development Status :: 4 - Beta",
    "Environment :: Console",
    "Intended Audience :: Information Technology",
    "Intended Audience :: System Administrators",
    "License :: OSI Approved :: Apache Software License",
    "Operating System :: Microsoft :: Windows",
    "Operating System :: POSIX :: Linux",
    "Operating System :: MacOS",
    "Programming Language :: Go",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
]
URLS = {
    "Homepage": "https://github.com/debugactiveprocess/MaldocTrace",
    "Changelog": "https://github.com/debugactiveprocess/MaldocTrace/blob/main/CHANGELOG.md",
    "Issues": "https://github.com/debugactiveprocess/MaldocTrace/issues",
}


def read(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


def binary_from_archive(path: str) -> bytes:
    """Return the maldocTrace executable stored in a release archive."""
    if path.endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if os.path.basename(n) == "maldocTrace.exe":
                    return z.read(n)
    else:
        with tarfile.open(path, "r:gz") as t:
            for m in t.getmembers():
                if m.isfile() and os.path.basename(m.name) == "maldocTrace":
                    f = t.extractfile(m)
                    assert f is not None
                    return f.read()
    raise SystemExit(f"{path}: no maldocTrace binary inside")


def metadata(version: str) -> bytes:
    lines = [
        "Metadata-Version: 2.1",
        f"Name: {NAME}",
        f"Version: {version}",
        f"Summary: {SUMMARY}",
        "Author: debugactiveprocess",
        "License: Apache-2.0",
        f"Keywords: {KEYWORDS}",
        "Requires-Python: >=3.8",
    ]
    lines += [f"Classifier: {c}" for c in CLASSIFIERS]
    lines += [f"Project-URL: {k}, {v}" for k, v in URLS.items()]
    lines.append("Description-Content-Type: text/markdown")
    body = read(os.path.join(HERE, "README.md")).decode("utf-8")
    return ("\n".join(lines) + "\n\n" + body).encode("utf-8")


def wheel_file(tags: list[str]) -> bytes:
    lines = ["Wheel-Version: 1.0", "Generator: maldoctrace build_wheels.py", "Root-Is-Purelib: false"]
    lines += [f"Tag: py3-none-{t}" for t in tags]
    return ("\n".join(lines) + "\n").encode()


def record_hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode()
    return f"sha256={digest}"


def build(version: str, goos: str, goarch: str, binary: bytes, out: str) -> str:
    tags = PLATFORMS[(goos, goarch)]
    exe = "maldoctrace.exe" if goos == "windows" else "maldoctrace"
    dist_info = f"{NAME}-{version}.dist-info"
    data_dir = f"{NAME}-{version}.data"

    init = read(os.path.join(HERE, NAME, "__init__.py")).decode("utf-8")
    init = init.replace('__version__ = "0.0.0"', f'__version__ = "{version}"', 1)
    files: list[tuple[str, bytes, int]] = [
        (f"{NAME}/__init__.py", init.encode("utf-8"), 0o644),
        (f"{NAME}/__main__.py", read(os.path.join(HERE, NAME, "__main__.py")), 0o644),
        (f"{data_dir}/scripts/{exe}", binary, 0o755),
        (f"{dist_info}/METADATA", metadata(version), 0o644),
        (f"{dist_info}/WHEEL", wheel_file(tags), 0o644),
        (f"{dist_info}/LICENSE", read(os.path.join(ROOT, "LICENSE")), 0o644),
        (f"{dist_info}/top_level.txt", f"{NAME}\n".encode(), 0o644),
    ]

    record = io.StringIO()
    w = csv.writer(record, lineterminator="\n")
    for name, data, _ in files:
        w.writerow([name, record_hash(data), len(data)])
    w.writerow([f"{dist_info}/RECORD", "", ""])
    files.append((f"{dist_info}/RECORD", record.getvalue().encode(), 0o644))

    filename = f"{NAME}-{version}-py3-none-{'.'.join(tags)}.whl"
    path = os.path.join(out, filename)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data, mode in files:
            info = zipfile.ZipInfo(name, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = (0o100000 | mode) << 16
            z.writestr(info, data)
    return path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--version", required=True)
    ap.add_argument("--dist", required=True, help="directory with the release archives")
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    built = 0
    for (goos, goarch) in PLATFORMS:
        stem = f"maldocTrace_{args.version}_{goos}_{goarch}"
        archive = None
        for ext in (".zip", ".tar.gz"):
            p = os.path.join(args.dist, stem + ext)
            if os.path.exists(p):
                archive = p
        if archive is None:
            raise SystemExit(f"missing release archive for {goos}/{goarch} ({stem}.*)")
        path = build(args.version, goos, goarch, binary_from_archive(archive), args.out)
        print(path)
        built += 1
    print(f"{built} wheels")


if __name__ == "__main__":
    main()
