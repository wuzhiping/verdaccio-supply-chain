#!/usr/bin/env python3
"""Python distribution helpers for the PyPI ecosystem; standard library only."""
import re, tarfile, zipfile

DIST_SUFFIXES = (".whl", ".tar.gz", ".zip", ".tar.bz2", ".egg")
WHEEL_RE = re.compile(r"^(?P<name>[^-]+)-(?P<version>[^-]+)(-(?P<build>\d[^-]*))?-[^-]+-[^-]+-[^-]+\.whl$", re.I)
SDIST_RE = re.compile(r"^(?P<name>.+)-(?P<version>[^-]+)\.(tar\.gz|zip|tar\.bz2|egg)$", re.I)


def normalize_name(name):
    """PEP 503 normalized name, this is what the OSV PyPI ecosystem uses."""
    return re.sub(r"[-_.]+", "-", str(name)).lower()


def parse_filename(filename):
    """Return (name, version) for a wheel or sdist filename."""
    match = WHEEL_RE.match(filename)
    if match:
        return match.group("name"), match.group("version")
    match = SDIST_RE.match(filename)
    if match:
        return match.group("name"), match.group("version")
    return None


def parse_metadata(raw):
    """Read the RFC822 style headers of a METADATA or PKG-INFO file."""
    head = raw.split("\n\n", 1)[0]
    fields = {}
    for line in head.splitlines():
        if not line.strip():
            continue
        if line[:1] in (" ", "\t") and fields:
            key = next(reversed(fields))
            if isinstance(fields[key], list):
                fields[key][-1] += " " + line.strip()
            else:
                fields[key] += " " + line.strip()
            continue
        key, sep, value = line.partition(":")
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if key in fields:
            if isinstance(fields[key], list):
                fields[key].append(value)
            else:
                fields[key] = [fields[key], value]
        else:
            fields[key] = value
    return fields


def read_metadata(path):
    """License, requirements and summary of a wheel or sdist."""
    name = path.name
    try:
        if name.lower().endswith(".whl"):
            with zipfile.ZipFile(path) as archive:
                for member in archive.namelist():
                    if member.endswith(".dist-info/METADATA"):
                        raw = archive.read(member)[: 2 * 1024 * 1024]
                        break
                else:
                    return None
        else:
            with tarfile.open(path, "r:*") as archive:
                for member in archive.getmembers():
                    if member.isfile() and member.name.endswith("PKG-INFO") and member.name.count("/") == 1:
                        stream = archive.extractfile(member)
                        raw = stream.read(2 * 1024 * 1024) if stream else b""
                        break
                else:
                    return None
    except Exception:
        return None
    fields = parse_metadata(raw.decode("utf-8", "ignore"))
    raw_requires = fields.get("requires-dist") or []
    if isinstance(raw_requires, str):
        raw_requires = [raw_requires]
    requires = []
    for item in raw_requires:
        for part in str(item).split(","):
            part = part.strip()
            if not part:
                continue
            spec = part.split(";", 1)[0].strip()
            name = spec.split()[0] if spec.split() else spec
            rest = spec[len(name):].strip()
            requires.append(f"{name}@{rest}" if rest else name)
    summary = ""
    body = raw.decode("utf-8", "ignore").split("\n\n", 1)
    if len(body) > 1:
        summary = " ".join(body[1].split())[:500]
    return {
        "license": (fields.get("license") or fields.get("license-expression") or "").strip()[:120] or "UNKNOWN",
        "requires": requires,
        "summary": summary,
        "requires_python": fields.get("requires-python", ""),
    }
