#!/usr/bin/env python3
"""Python distribution helpers for the PyPI ecosystem; standard library only."""
import io, json, re, tarfile, urllib.error, urllib.parse, urllib.request, zipfile

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


def version_key(version):
    """Sortable key of a python version, used to find the latest one."""
    parts = re.split(r"[.\-+]", str(version))
    key = []
    for part in parts:
        if part.isdigit():
            key.append((1, int(part), ""))
        elif part:
            key.append((0, 0, part))
    return tuple(key)


def is_distribution(path):
    """True for a wheel or sdist, false for the metadata sidecar files."""
    name = str(path).lower()
    if name.endswith(".metadata"):
        return False
    return name.endswith(DIST_SUFFIXES)


def nexus_split(base_url):
    """Split a Nexus repository url into (server url, repository name)."""
    url = str(base_url).strip().rstrip("/")
    if "/repository/" in url:
        server, _, tail = url.partition("/repository/")
        repo = tail.strip("/").split("/")[0]
        return server, repo
    return url.rsplit("/", 1)[0], url.rsplit("/", 1)[-1]


def nexus_search(base_url, timeout=30, limit=100000, server=None, repo=None):
    """Yield the components of a Nexus pypi repository through the REST search."""
    if server is None or repo is None:
        server, repo = nexus_split(base_url)
    token = None
    count = 0
    while True:
        params = {"repository": repo, "format": "pypi"}
        if token:
            params["continuationToken"] = token
        url = f"{server}/service/rest/v1/search?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "sbom-scanner/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
        for item in data.get("items") or []:
            yield item
            count += 1
        token = data.get("continuationToken")
        if not token or count >= limit:
            break


def fetch(url, timeout=30, limit=4 * 1024 * 1024):
    """Download a file, at most `limit` bytes."""
    req = urllib.request.Request(url, headers={"User-Agent": "sbom-scanner/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.read(limit)


def metadata_document(raw):
    """License, requirements and summary of a METADATA document."""
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


def metadata_from_bytes(raw, filename):
    """Read the metadata of a wheel or sdist that was downloaded."""
    if raw is None:
        return None
    name = str(filename).lower()
    if name.endswith(".metadata") or not name.endswith(DIST_SUFFIXES):
        # a pep 658 metadata file, it is the document itself
        return metadata_document(raw)
    try:
        if name.endswith(".whl"):
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for member in archive.namelist():
                    if member.endswith(".dist-info/METADATA"):
                        return metadata_document(archive.read(member)[: 2 * 1024 * 1024])
            return None
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:*") as archive:
            for member in archive.getmembers():
                if member.isfile() and member.name.endswith("PKG-INFO") and member.name.count("/") == 1:
                    stream = archive.extractfile(member)
                    raw_doc = stream.read(2 * 1024 * 1024) if stream else b""
                    return metadata_document(raw_doc)
    except Exception:
        return None
    return None
