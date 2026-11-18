"""GitHub-only, no-redirect downloader. A remote scan fetches a pinned commit ZIP."""
from __future__ import annotations
import re
import urllib.error
import urllib.parse
import urllib.request
from .safeio import MAX_ARCHIVE, UnsafeInput

REPO_RE = re.compile(r"^(?:https://github\.com/)?([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})(?:\.git)?/?$")
SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+/-]{0,127}$")
ALLOWED = {"api.github.com", "codeload.github.com"}
ASSET_HOSTS = {"release-assets.githubusercontent.com", "objects.githubusercontent.com"}

class SafeAssetRedirect(urllib.request.HTTPRedirectHandler):
    """Allow only GitHub's release storage endpoints, never forward API credentials."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        assert_url(newurl, asset_storage=True)
        if urllib.parse.urlsplit(req.full_url).hostname != 'api.github.com':
            raise UnsafeInput('chained release-asset redirect refused')
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new:
            new.remove_header('Authorization')
        return new

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        raise UnsafeInput('remote redirect refused')

OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
ASSET_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), SafeAssetRedirect)

def assert_url(url: str, *, asset_storage: bool = False) -> None:
    u = urllib.parse.urlsplit(url)
    hosts = ASSET_HOSTS if asset_storage else ALLOWED
    if (u.scheme != "https" or u.hostname not in hosts or u.username or u.password
            or u.port not in (None, 443) or u.fragment):
        raise UnsafeInput("network destination not allowed")


def get_bytes(url: str, cap: int, token: str | None = None, *,
              accept: str = 'application/vnd.github+json', allow_asset_redirect: bool = False) -> bytes:
    assert_url(url)
    if cap <= 0 or cap > MAX_ARCHIVE:
        raise UnsafeInput('invalid response size limit')
    if allow_asset_redirect and (urllib.parse.urlsplit(url).hostname != 'api.github.com'
        or not re.fullmatch(r'/repos/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/releases/assets/[0-9]+',
                            urllib.parse.urlsplit(url).path)):
        raise UnsafeInput('asset redirects only accepted for GitHub release API')
    headers = {'User-Agent': 'geordi/0.4', 'Accept': accept}
    if token and urllib.parse.urlsplit(url).hostname == 'api.github.com':
        headers['Authorization'] = 'Bearer ' + token
    request = urllib.request.Request(url, headers=headers)
    opener = ASSET_OPENER if allow_asset_redirect else OPENER
    try:
        with opener.open(request, timeout=20) as response:
            if not allow_asset_redirect and urllib.parse.urlsplit(response.url).hostname != urllib.parse.urlsplit(url).hostname:
                raise UnsafeInput('unexpected redirected host')
            data = response.read(cap + 1)
            if len(data) > cap:
                raise UnsafeInput('network response exceeds limit')
            if allow_asset_redirect and data[:1] == b'{' and b'"message"' in data[:300]:
                raise UnsafeInput('GitHub did not provide binary release asset')
            return data
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            raise UnsafeInput('GitHub resource not found') from exc
        # URLs and response bodies can carry credentials: never include them in errors.
        raise UnsafeInput(f'GitHub HTTP error {exc.code}') from exc
    except urllib.error.URLError as exc:
        raise UnsafeInput('GitHub network request failed') from exc

