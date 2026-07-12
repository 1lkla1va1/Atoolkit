"""Shared authorization-scope parsing and URL matching.

Security-sensitive callers must compare parsed authorities, never substrings.
An exact host scope does not implicitly authorize sibling/suffix domains.
Subdomains require an explicit ``*.example.com`` scope.  A scope derived from
an absolute target URL pins the effective port (80/443 when omitted).
"""
from __future__ import annotations

import ipaddress
import posixpath
import re
from dataclasses import dataclass
from urllib.parse import unquote, urlsplit


_METHOD_PREFIX = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+", re.IGNORECASE
)
_DEFAULT_PORTS = {"http": 80, "https": 443}


@dataclass(frozen=True)
class AuthorizedScope:
    host: str
    port: int | None = None
    include_subdomains: bool = False
    scheme: str = ""
    path_prefix: str = "/"


@dataclass(frozen=True)
class ParsedURL:
    host: str
    port: int
    scheme: str
    path: str


def _normalize_host(value: str) -> str:
    host = str(value or "").strip().rstrip(".").lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if not host:
        return ""
    try:
        return ipaddress.ip_address(host).compressed.lower()
    except ValueError:
        pass
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return ""


def _strip_method(value: str) -> str:
    text = str(value or "").strip().splitlines()[0].strip()
    return _METHOD_PREFIX.sub("", text, count=1).strip()


def _normalize_path(value: str) -> str:
    path = str(value or "/")
    # Decode a small, bounded number of layers so encoded dot/slash segments
    # cannot escape an authorized subsystem prefix.
    for _ in range(3):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    if not path.startswith("/"):
        path = "/" + path
    normalized = posixpath.normpath(path)
    return normalized if normalized.startswith("/") else "/" + normalized


def parse_http_url(value: str) -> ParsedURL | None:
    """Parse an absolute HTTP(S) URL and reject ambiguous userinfo/ports."""
    text = _strip_method(value)
    try:
        parsed = urlsplit(text)
        scheme = parsed.scheme.lower()
        if scheme not in _DEFAULT_PORTS or not parsed.hostname:
            return None
        if parsed.username is not None or parsed.password is not None:
            return None
        host = _normalize_host(parsed.hostname)
        if not host:
            return None
        port = parsed.port or _DEFAULT_PORTS[scheme]
    except (TypeError, ValueError):
        return None
    return ParsedURL(host=host, port=port, scheme=scheme,
                     path=_normalize_path(parsed.path or "/"))


def parse_authorized_scope(value: str) -> AuthorizedScope | None:
    """Parse ``host``, ``host:port``, ``*.host`` or an absolute URL scope."""
    text = _strip_method(value)
    if not text:
        return None
    include_subdomains = False
    if text.startswith("*."):
        include_subdomains = True
        text = text[2:]

    parsed_url = parse_http_url(text)
    if parsed_url:
        return AuthorizedScope(
            parsed_url.host, parsed_url.port, include_subdomains,
            parsed_url.scheme, parsed_url.path,
        )

    # urlsplit with a scheme-relative prefix safely handles IPv6 brackets and
    # host:port forms without treating the host as a URL scheme.
    try:
        parsed = urlsplit("//" + text)
        if (not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path not in ("", "/")):
            return None
        host = _normalize_host(parsed.hostname)
        port = parsed.port
    except (TypeError, ValueError):
        return None
    if not host:
        return None
    # Wildcards are meaningful only for DNS names.
    if include_subdomains:
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
    return AuthorizedScope(host, port, include_subdomains)


def format_scope(scope: AuthorizedScope) -> str:
    host = f"[{scope.host}]" if ":" in scope.host else scope.host
    prefix = "*." if scope.include_subdomains else ""
    authority = f"{prefix}{host}:{scope.port}" if scope.port is not None else prefix + host
    if scope.scheme:
        return f"{scope.scheme}://{authority}{scope.path_prefix or '/'}"
    return authority


def authorization_scope_from_url(value: str) -> str:
    """Return a strict host+effective-port scope derived from a target URL."""
    parsed = parse_http_url(value)
    if not parsed:
        return ""
    return format_scope(AuthorizedScope(
        parsed.host, parsed.port, False, parsed.scheme, parsed.path,
    ))


def hostname_from_url(value: str) -> str:
    parsed = parse_http_url(value)
    return parsed.host if parsed else ""


def normalize_authorized_scopes(values: list[str]) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for value in values:
        scope = parse_authorized_scope(value)
        if not scope:
            continue
        formatted = format_scope(scope)
        if formatted not in seen:
            seen.add(formatted)
            out.append(formatted)
    return out


def is_authorized_url(value: str, authorized_scopes: list[str]) -> bool:
    """Return whether an absolute URL is inside one of the parsed scopes."""
    parsed = parse_http_url(value)
    if not parsed:
        return False
    for raw in authorized_scopes or []:
        scope = parse_authorized_scope(raw)
        if not scope:
            continue
        host_ok = parsed.host == scope.host
        if scope.include_subdomains:
            host_ok = parsed.host.endswith("." + scope.host)
        scheme_ok = not scope.scheme or parsed.scheme == scope.scheme
        port_ok = scope.port is None or parsed.port == scope.port
        path_ok = True
        if scope.scheme:
            prefix = _normalize_path(scope.path_prefix or "/")
            path_ok = (prefix == "/" or parsed.path == prefix
                       or parsed.path.startswith(prefix.rstrip("/") + "/"))
        if host_ok and scheme_ok and port_ok and path_ok:
            return True
    return False


def host_header_matches_url(host_header: str, value: str) -> bool:
    """Reject virtual-host confusion between an explicit Host header and URL."""
    parsed = parse_http_url(value)
    scope = parse_authorized_scope(host_header)
    if not parsed or not scope or scope.include_subdomains or scope.scheme:
        return False
    return parsed.host == scope.host and (scope.port is None or parsed.port == scope.port)
