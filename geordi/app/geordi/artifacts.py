"""Resolve installable Marketplace payloads without running source or trusting asset URLs.

Selection follows documented release ZIP/card asset conventions. Ambiguous layouts
are refused rather than silently scanning a different payload. A matched upstream
asset is not proof Home Assistant has installed identical bytes locally.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

from .github import get_bytes, REPO_RE, REF_RE, SHA_RE
from .safeio import MAX_ARCHIVE, MAX_EXPANDED, UnsafeInput, unzip_safely

_API = 'https://api.github.com'
_PATH_NAME = re.compile(r'^[A-Za-z0-9_][A-Za-z0-9_.-]{0,180}$')


@dataclass(frozen=True)
class InstallTarget:
    root: Path
    sha: str
    label: str
    kind: str
    selection: str
    artifact_sha256: str
    parity: str
    notes: tuple[str, ...] = ()


def _repo(repo: str) -> tuple[str, str]:
    match = REPO_RE.fullmatch(repo)
    if not match:
        raise UnsafeInput('expected GitHub owner/repository')
    owner, name = match.groups()
    name = name.removesuffix('.git')
    if any(part in ('.', '..') or '..' in part for part in (owner, name)):
        raise UnsafeInput('invalid GitHub repository name')
    return owner, name


def _json(url: str, cap: int, token: str | None) -> dict:
    try:
        obj = json.loads(get_bytes(url, cap, token))
    except (ValueError, UnicodeError) as exc:
        raise UnsafeInput('GitHub metadata was not valid JSON') from exc
    if not isinstance(obj, dict):
        raise UnsafeInput('GitHub metadata was not a JSON object')
    return obj


def _read_hacs(root: Path) -> dict:
    path = root / 'hacs.json'
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UnsafeInput('This repository version has no readable hacs.json') from exc
    if len(raw) > 64 * 1024:
        raise UnsafeInput('hacs.json exceeds size limit')
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeError) as exc:
        raise UnsafeInput('invalid hacs.json') from exc
    if not isinstance(obj, dict):
        raise UnsafeInput('hacs.json is not an object')
    return obj


def _source_root(root: Path, kind: str, config: dict, repo_name: str) -> tuple[Path, str]:
    if kind == 'integration':
        if config.get('content_in_root') is True:
            if not (root / 'manifest.json').is_file():
                raise UnsafeInput('content_in_root integration lacks manifest.json')
            return root, 'integration_source_root'
        components = root / 'custom_components'
        if not components.is_dir() or components.is_symlink():
            raise UnsafeInput('integration custom_components directory unavailable')
        matches = sorted(x for x in components.iterdir() if x.is_dir() and not x.is_symlink()
                         and (x / 'manifest.json').is_file())
        if len(matches) != 1:
            raise UnsafeInput('missing or ambiguous integration directories')
        return matches[0], 'integration_source_directory'
    if kind == 'card':
        root_only = config.get('content_in_root') is True
        candidates = [root] if root_only else [root, root / 'dist']
        names = _card_names(repo_name, config)
        for loc in candidates:
            if not loc.is_dir() or loc.is_symlink():
                continue
            if any((loc / filename).is_file() and not (loc / filename).is_symlink() for filename in names):
                return loc, 'card_source_root' if loc == root else 'card_source_dist'
        raise UnsafeInput('card bundle not found in source root/dist')
    raise UnsafeInput('unsupported Marketplace category')


def _card_names(repo_name: str, config: dict) -> list[str]:
    filename = config.get('filename')
    if isinstance(filename, str):
        if not _PATH_NAME.fullmatch(filename) or not filename.endswith('.js'):
            raise UnsafeInput('invalid card filename in hacs.json')
        return [filename]
    base = repo_name.removeprefix('lovelace-')
    return list(dict.fromkeys((base + '.js', repo_name + '.js',
                               repo_name + '.umd.js', repo_name + '-bundle.js')))


def _safe_asset(asset: dict, *, required_name: str | None = None) -> tuple[str, int, int]:
    name, identity, size = asset.get('name'), asset.get('id'), asset.get('size')
    if (not isinstance(name, str) or not _PATH_NAME.fullmatch(name)
            or name.startswith('.') or not isinstance(identity, int) or isinstance(identity, bool)
            or identity <= 0 or not isinstance(size, int) or isinstance(size, bool)
            or size < 0 or size > MAX_ARCHIVE):
        raise UnsafeInput('release contains invalid asset metadata')
    if required_name is not None and name != required_name:
        raise UnsafeInput('release asset name mismatch')
    return name, identity, size


def _download_asset(owner: str, name: str, asset: dict, dest: Path, token: str | None) -> str:
    asset_name, asset_id, expected_size = _safe_asset(asset)
    if dest.name != asset_name:
        raise UnsafeInput('asset destination mismatch')
    url = f'{_API}/repos/{owner}/{name}/releases/assets/{asset_id}'
    data = get_bytes(url, MAX_ARCHIVE, token, accept='application/octet-stream', allow_asset_redirect=True)
    if len(data) != expected_size:
        raise UnsafeInput('release asset size differs from GitHub metadata')
    digest = hashlib.sha256(data).hexdigest()
    expected_hash = asset.get('digest')
    if isinstance(expected_hash, str) and expected_hash.startswith('sha256:'):
        if digest != expected_hash.removeprefix('sha256:').lower():
            raise UnsafeInput('release asset digest mismatch')
    dest.write_bytes(data)
    return digest


def _release_asset(release: dict | None, filename: str) -> dict:
    if not release:
        raise UnsafeInput('requested installable artifact requires a published release')
    assets = release.get('assets')
    if not isinstance(assets, list) or len(assets) > 200:
        raise UnsafeInput('invalid or excessive GitHub release assets')
    matches = [a for a in assets if isinstance(a, dict) and a.get('name') == filename]
    if len(matches) != 1:
        raise UnsafeInput('required release asset missing or ambiguous')
    _safe_asset(matches[0], required_name=filename)
    return matches[0]


def _zip_content_root(extracted: Path) -> Path:
    """Allow flat integration files, one domain wrapper, or custom_components/domain."""
    candidates: list[Path] = []
    if (extracted / 'manifest.json').is_file():
        candidates.append(extracted)
    for top in extracted.iterdir():
        if not top.is_dir() or top.is_symlink():
            continue
        if (top / 'manifest.json').is_file():
            candidates.append(top)
        if top.name == 'custom_components':
            candidates.extend(p for p in top.iterdir() if p.is_dir() and not p.is_symlink()
                              and (p / 'manifest.json').is_file())
    if len(candidates) != 1:
        raise UnsafeInput('ZIP release has missing or ambiguous integration manifest')
    return candidates[0]


def _unpack_source(owner: str, name: str, sha: str, work: Path) -> tuple[Path, str]:
    source_data = get_bytes(f'https://codeload.github.com/{owner}/{name}/zip/{sha}', MAX_ARCHIVE)
    source_hash = hashlib.sha256(source_data).hexdigest()
    archive = work / 'source.zip'
    archive.write_bytes(source_data)
    unpacked = work / 'source'
    try:
        unzip_safely(archive, unpacked)
    except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
        raise UnsafeInput('GitHub source archive is invalid') from exc
    tops = list(unpacked.iterdir())
    root = tops[0] if len(tops) == 1 and tops[0].is_dir() else unpacked
    return root, source_hash


def load_installable(repo: str, ref: str | None, kind: str, work: Path,
                     *, token: str | None = None) -> InstallTarget:
    """Fetch a pinned release artifact or source candidate; never execute its contents.

    A published release payload may be selected and its digest recorded, but local
    installed byte parity is never claimed without reading the HA config directory.
    Source-layout choices are marked approximate.
    """
    owner, name = _repo(repo)
    if kind not in ('integration', 'card'):
        raise UnsafeInput('kind must be integration or card')
    if ref is None:
        latest = _json(f'{_API}/repos/{owner}/{name}/releases/latest', 512 * 1024, token)
        ref = latest.get('tag_name')
    if not isinstance(ref, str) or not REF_RE.fullmatch(ref) or '..' in ref:
        raise UnsafeInput('invalid Git reference')
    encoded_ref = quote(ref, safe='')
    commit = _json(f'{_API}/repos/{owner}/{name}/commits/{encoded_ref}', 1024 * 1024, token)
    sha = commit.get('sha', '')
    if not isinstance(sha, str) or not SHA_RE.fullmatch(sha):
        raise UnsafeInput('invalid pinned commit returned from GitHub')
    # GitHub can return a commit ref without a release; treat 404 only as a missing
    # release. Errors such as 403/rate limiting must not downgrade to source.
    release = None
    try:
        release = _json(f'{_API}/repos/{owner}/{name}/releases/tags/{encoded_ref}',
                        512 * 1024, token)
    except UnsafeInput as exc:
        if str(exc) != 'GitHub resource not found':
            raise
    src, source_hash = _unpack_source(owner, name, sha, work)
    config = _read_hacs(src)
    label = f'{owner}/{name}@{ref}'
    if kind == 'integration' and config.get('zip_release') is True:
        filename = config.get('filename')
        if not isinstance(filename, str) or not _PATH_NAME.fullmatch(filename) or not filename.endswith('.zip'):
            raise UnsafeInput('invalid integration ZIP release filename')
        asset = _release_asset(release, filename)
        asset_path = work / filename
        digest = _download_asset(owner, name, asset, asset_path, token)
        release_dir = work / 'release'
        try:
            unzip_safely(asset_path, release_dir)
        except (zipfile.BadZipFile, RuntimeError, OSError) as exc:
            raise UnsafeInput('GitHub release ZIP is invalid') from exc
        return InstallTarget(_zip_content_root(release_dir), sha, label, kind,
                             'integration_release_zip', digest, 'local-installation-not-compared')
    if kind == 'card' and config.get('content_in_root') is not True and release:
        names = _card_names(name, config)
        assets = release.get('assets')
        if not isinstance(assets, list) or len(assets) > 200:
            raise UnsafeInput('invalid release asset list')
        selected = next((a for filename in names for a in assets
                         if isinstance(a, dict) and a.get('name') == filename), None)
        if selected:
            if len(assets) > 40 or sum(a.get('size', MAX_ARCHIVE + 1) for a in assets
                                       if isinstance(a, dict) and isinstance(a.get('size'), int)) > MAX_EXPANDED:
                raise UnsafeInput('release assets exceed safe download budget')
            install = work / 'card_assets'
            install.mkdir()
            hashes = []
            for asset in assets:
                if not isinstance(asset, dict):
                    raise UnsafeInput('release includes invalid asset entry')
                asset_name, _id, _size = _safe_asset(asset)
                if (install / asset_name).exists():
                    raise UnsafeInput('duplicate release asset name')
                hashes.append((asset_name, _download_asset(owner, name, asset, install / asset_name, token)))
            # Fingerprint includes every asset name and digest, since Marketplace may
            # install resources alongside the selected JavaScript bundle.
            fingerprint = hashlib.sha256(json.dumps(sorted(hashes)).encode()).hexdigest()
            return InstallTarget(install, sha, label, kind, 'card_release_assets', fingerprint,
                                 'local-installation-not-compared', (f'entrypoint:{selected["name"]}',))
    chosen, selection = _source_root(src, kind, config, name)
    # Do not call these 'verified installed bytes': content_in_root, dist selection and
    # HA's processing can differ from the upstream source checkout.
    return InstallTarget(chosen, sha, label, kind, selection, source_hash,
                         'source-layout-approximate',
                         ('Source layout projected; installed bytes not available',))
