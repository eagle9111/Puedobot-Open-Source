"""Conservative npm identity/version evidence; never install or resolve remotely."""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from urllib.parse import urlsplit

from app.core.paths import open_text_under

_NAME = r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*"
_ALIAS = re.compile(rf"npm:({_NAME})@(.+)")
_VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
_JSON_KEY = re.compile(r'"((?:[^"\\]|\\.)*)"\s*:')


@dataclass(frozen=True)
class NpmDependency:
    name: str
    version: str
    file_path: str
    line: int
    evidence: str


def _exact_version(spec: object) -> str | None:
    if not isinstance(spec, str):
        return None
    version = spec.strip()
    if version.startswith("="):
        version = version[1:].strip()
    if version.startswith("v"):
        version = version[1:]
    match = _VERSION.fullmatch(version)
    if match is None:
        return None
    if match[4] and any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in match[4].split(".")):
        return None
    return version


def _read_json(path: Path) -> tuple[dict | None, str]:
    try:
        with open_text_under(path.absolute().parent, path.absolute()) as handle:
            text = handle.read()
        data = json.loads(text)
    except (OSError, ValueError):
        return None, ""
    return (data if isinstance(data, dict) else None), text


def _locations(text: str) -> dict[str, tuple[int, str]]:
    """Index JSON keys once, avoiding a full text search for each dependency."""
    locations: dict[str, tuple[int, str]] = {}
    for line_number, line in enumerate(text.splitlines(), 1):
        for match in _JSON_KEY.finditer(line):
            try:
                name = json.loads(f'"{match[1]}"')
            except ValueError:
                continue
            locations.setdefault(name, (line_number, line.rstrip()))
    return locations


def parse_npm_manifest(path: str, *, allow_lockfile: bool = True) -> tuple[list[NpmDependency], list[str]]:
    """Read direct dependencies/devDependencies using exact pins or a v2/v3 lock.

    Lockfile evidence is the recorded dependency tree, not proof of what is
    currently deployed. Workspaces, local/Git/tarball sources, older lock formats,
    other package-manager locks and transitive dependency enumeration are outside
    this parser's supported scope. Unknown evidence is skipped with a notice.
    """
    manifest = Path(path)
    data, text = _read_json(manifest)
    if data is None:
        return [], ["package.json: skipped; manifest is unreadable or is not a JSON object."]
    notices: list[str] = []
    manifest_locations = _locations(text)
    lock_path: Path | None = None
    packages: dict = {}
    lock_locations: dict[str, tuple[int, str]] = {}
    # npm-shrinkwrap takes precedence, including when unreadable or unsupported.
    for filename in (("npm-shrinkwrap.json", "package-lock.json") if allow_lockfile else ()):
        candidate = manifest.parent / filename
        if not candidate.exists() and not candidate.is_symlink():
            continue
        lock, lock_text = _read_json(candidate)
        if lock is not None and lock.get("lockfileVersion") in (2, 3) and isinstance(lock.get("packages"), dict):
            lock_path = candidate
            packages = lock["packages"]
            lock_locations = _locations(lock_text)
        else:
            notices.append(f"{filename}: skipped; only readable npm v2/v3 package maps are supported.")
        break

    declarations: dict[str, tuple[object, str]] = {}
    conflicts: set[str] = set()
    for section in ("dependencies", "devDependencies"):
        values = data.get(section, {})
        if not isinstance(values, dict):
            notices.append(f"package.json: {section} skipped; expected an object.")
            continue
        for name, spec in values.items():
            if name in declarations and declarations[name][0] != spec:
                conflicts.add(name)
            declarations[name] = (spec, section)

    dependencies: list[NpmDependency] = []
    for slot, (spec, section) in declarations.items():
        reason = "exact registry package/version not established"
        name = slot
        supported = re.fullmatch(_NAME, slot) is not None and isinstance(spec, str) and slot not in conflicts
        if supported:
            spec = spec.strip()
            if spec.startswith("npm:"):
                alias = _ALIAS.fullmatch(spec)
                if alias is None:
                    supported = False
                else:
                    name, version_spec = alias.groups()
            else:
                version_spec = spec
            if supported and any(character in version_spec for character in ":/\\"):
                supported = False
        if not supported:
            notices.append(f"package.json: {slot} skipped ({reason}).")
            continue

        version = _exact_version(version_spec)
        source = manifest
        line, raw = manifest_locations.get(slot, (1, ""))
        entry_path = f"node_modules/{slot}"
        locked = packages.get(entry_path)
        root = packages.get("", {})
        root_specs = root.get(section, {}) if isinstance(root, dict) else {}
        if lock_path is not None and isinstance(root_specs, dict) and root_specs.get(slot) == declarations[slot][0] and locked is not None:
            # A linked/forked source or conflicting identity must not fall back
            # to a public-registry assertion merely because it has a version.
            if not isinstance(locked, dict) or locked.get("link") or locked.get("name", name) != name:
                notices.append(f"{lock_path.name}: {slot} skipped (linked or conflicting package identity).")
                continue
            resolved = locked.get("resolved")
            if resolved is not None:
                try:
                    registry = urlsplit(resolved) if isinstance(resolved, str) else None
                except ValueError:
                    registry = None
                if registry is None or registry.scheme != "https" or registry.hostname != "registry.npmjs.org":
                    notices.append(f"{lock_path.name}: {slot} skipped (non-registry source).")
                    continue
            locked_version = _exact_version(locked.get("version"))
            if locked_version is None or (version is not None and version != locked_version):
                notices.append(f"{lock_path.name}: {slot} skipped (invalid version or conflict with exact pin).")
                continue
            if slot != name and locked.get("name") != name:
                notices.append(f"{lock_path.name}: {slot} skipped (alias target identity not recorded).")
                continue
            version = locked_version
            source = lock_path
            line, raw = lock_locations.get(entry_path, (1, ""))
            raw = f"{raw}\n# {entry_path}: recorded registry package {name}@{version}"
        elif version is None:
            reason = "no matching supported lock entry; exact version not established"
        if version is None:
            notices.append(f"package.json: {slot} skipped ({reason}).")
            continue
        dependencies.append(NpmDependency(name, version, str(source), line, raw))
    return dependencies, notices
