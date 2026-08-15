"""Loopback-only autonomous web lab worker for controlled security benchmarks.

The worker is deliberately restricted to localhost/loopback. It performs bounded
black-box discovery for isolated Docker/CTF targets and records replayable evidence.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass, field
from html.parser import HTMLParser
from http.cookiejar import CookieJar
from typing import Iterable

_FLAG_PATTERNS = (
    re.compile(r"(?i)\b(?:flag|xben)[\s:=_-]*\{[^{}\r\n]{4,256}\}"),
    re.compile(r"(?i)\bflag[\s:=_-]+([A-Za-z0-9_./+\-=]{8,256})"),
)
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
_ID_CONTEXT = re.compile(r"(?i)(?:order(?:\s+id)?|trade(?:\s+id)?|\bid\b)[^0-9]{0,24}(\d{1,10})")


@dataclass(frozen=True)
class Form:
    action: str
    method: str
    fields: tuple[tuple[str, str], ...]
    values: tuple[tuple[str, str], ...] = ()

    def field_names(self) -> tuple[str, ...]:
        return tuple(name for name, _ in self.fields if name)

    def value_map(self) -> dict[str, str]:
        return dict(self.values)


@dataclass(frozen=True)
class ResponseEvidence:
    method: str
    url: str
    status: int
    body_sha256: str
    body_length: int
    title: str = ""
    flag: str = ""


@dataclass
class LabSolveResult:
    target: str
    solved: bool = False
    flag: str = ""
    authenticated: bool = False
    credential_username: str = ""
    requests: int = 0
    pages: int = 0
    id_mutations: int = 0
    evidence: list[ResponseEvidence] = field(default_factory=list)
    root_forms: list[dict] = field(default_factory=list)
    auth_transitions: list[dict] = field(default_factory=list)
    observations: list[dict] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False, indent=2)


class _PageParser(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base = base
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._form_action = ""
        self._form_method = "GET"
        self._fields: list[tuple[str, str]] | None = None
        self._values: list[tuple[str, str]] | None = None
        self._in_title = False
        self.title_parts: list[str] = []

    @property
    def title(self) -> str:
        return " ".join("".join(self.title_parts).split())

    def handle_starttag(self, tag: str, attrs) -> None:
        data = dict(attrs)
        tag = tag.lower()
        if tag == "a" and data.get("href"):
            self.links.append(urllib.parse.urljoin(self.base, data["href"]))
        elif tag == "form":
            self._form_action = urllib.parse.urljoin(self.base, data.get("action") or self.base)
            self._form_method = (data.get("method") or "GET").upper()
            self._fields = []
            self._values = []
        elif tag in {"input", "select", "textarea", "button"} and self._fields is not None:
            name = data.get("name") or ""
            typ = (data.get("type") or tag).lower()
            if name:
                self._fields.append((name, typ))
                if "value" in data and self._values is not None:
                    self._values.append((name, data.get("value") or ""))
        elif tag == "title":
            self._in_title = True

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag == "form" and self._fields is not None:
            self.forms.append(Form(
                self._form_action,
                self._form_method,
                tuple(self._fields),
                tuple(self._values or ()),
            ))
            self._fields = None
            self._values = None
        elif tag == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title_parts.append(data)


def _is_loopback_host(host: str) -> bool:
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    addresses = {item[4][0] for item in infos}
    return bool(addresses) and all(ipaddress.ip_address(x).is_loopback for x in addresses)


def assert_loopback_target(target: str) -> None:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise PermissionError("local lab target must be an absolute http(s) URL")
    if not _is_loopback_host(parsed.hostname):
        raise PermissionError("local lab worker refuses every non-loopback target")


def _same_origin(root: str, url: str) -> bool:
    a, b = urllib.parse.urlparse(root), urllib.parse.urlparse(url)
    return (a.scheme, a.hostname, a.port) == (b.scheme, b.hostname, b.port)


def _find_flag(body: str) -> str:
    for rx in _FLAG_PATTERNS:
        match = rx.search(body)
        if match:
            return match.group(0)
    return ""


def _user_form(forms: Iterable[Form]) -> Form | None:
    for form in forms:
        names = {x.lower() for x in form.field_names()}
        has_user = any(
            x in {"username", "user", "email", "login"} or "user" in x or "login" in x
            for x in names
        )
        if form.method == "POST" and has_user:
            return form
    return None


def _password_form(forms: Iterable[Form]) -> Form | None:
    for form in forms:
        names = {x.lower() for x in form.field_names()}
        types = {typ.lower() for _, typ in form.fields}
        if form.method == "POST" and ("password" in types or any("pass" in x for x in names)):
            return form
    return None


def _has_password_field(form: Form) -> bool:
    return _password_form((form,)) is not None


def default_credentials() -> tuple[tuple[str, str], ...]:
    return (
        ("admin", "admin"), ("admin", "password"), ("admin", "123456"),
        ("administrator", "administrator"), ("administrator", "password"),
        ("trader", "trader"), ("trader", "password"),
        ("demo", "demo"), ("demo", "password"),
        ("test", "test"), ("test", "password"),
        ("guest", "guest"), ("user", "user"), ("user", "password"),
    )


def _usernames() -> tuple[str, ...]:
    return tuple(dict.fromkeys(user for user, _ in default_credentials()))


def _passwords_for(username: str) -> tuple[str, ...]:
    preferred = [pwd for user, pwd in default_credentials() if user == username]
    generic = [username, "password", "admin", "123456", "test", "demo", "guest"]
    return tuple(dict.fromkeys([*preferred, *generic]))


class LocalLabWebAgent:
    def __init__(self, target: str, *, max_requests: int = 120, timeout: float = 5.0) -> None:
        assert_loopback_target(target)
        self.target = target
        self.max_requests = max(1, int(max_requests))
        self.timeout = timeout
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.result = LabSolveResult(target=target)

    def _request(self, method: str, url: str, data: dict[str, str] | None = None) -> tuple[str, _PageParser, ResponseEvidence]:
        if self.result.requests >= self.max_requests:
            raise RuntimeError("local lab request budget exhausted")
        if not _same_origin(self.target, url):
            raise PermissionError("local lab worker refuses cross-origin requests")
        method = method.upper()
        if method in _MUTATING and method != "POST":
            raise PermissionError("local lab worker only permits POST for login forms")
        payload = None
        headers = {"User-Agent": "APEX-LocalLab/1.0"}
        if data is not None:
            payload = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        self.result.requests += 1
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(2_000_000)
                status = int(getattr(resp, "status", 200))
                final_url = resp.geturl()
        except urllib.error.HTTPError as exc:
            raw = exc.read(2_000_000)
            status = int(exc.code)
            final_url = exc.geturl()
        if not _same_origin(self.target, final_url):
            raise PermissionError("local lab redirect escaped origin")
        body = raw.decode("utf-8", "replace")
        parser = _PageParser(final_url)
        parser.feed(body)
        flag = _find_flag(body)
        ev = ResponseEvidence(
            method=method,
            url=final_url,
            status=status,
            body_sha256=hashlib.sha256(raw).hexdigest(),
            body_length=len(raw),
            title=parser.title,
            flag=flag,
        )
        self.result.evidence.append(ev)
        self.result.observations.append({
            "method": method,
            "url": final_url,
            "title": parser.title,
            "links": sorted(set(parser.links))[:50],
            "forms": [
                {"action": f.action, "method": f.method, "fields": list(f.fields), "values": list(f.values)}
                for f in parser.forms
            ][:20],
            "numeric_hints": sorted(set(_ID_CONTEXT.findall(body)))[:50],
        })
        if flag:
            self.result.solved = True
            self.result.flag = flag
        return body, parser, ev

    @staticmethod
    def _login_payload(form: Form, username: str, password: str) -> dict[str, str]:
        payload: dict[str, str] = form.value_map()
        for name, typ in form.fields:
            lower = name.lower()
            if typ == "password" or "pass" in lower:
                payload[name] = password
            elif lower in {"username", "user", "email", "login"} or "user" in lower or "login" in lower:
                payload[name] = username
            elif typ in {"submit", "button"} and not payload.get(name):
                payload[name] = "Login"
            else:
                payload.setdefault(name, "")
        return payload

    @staticmethod
    def _authenticated(reference: ResponseEvidence, parser: _PageParser, body: str) -> bool:
        if _find_flag(body):
            return True
        if _user_form(parser.forms) is None and _password_form(parser.forms) is None:
            if parser.title and parser.title != reference.title:
                return True
            if re.search(r"(?i)\b(logout|sign out|dashboard|portfolio|account|trades?)\b", body):
                return True
        return False

    def _authenticate(self, login: Form, root_ev: ResponseEvidence) -> _PageParser | None:
        if _has_password_field(login):
            for username, password in default_credentials():
                body, parser, ev = self._request("POST", login.action, self._login_payload(login, username, password))
                self.result.auth_transitions.append({"username": username, "stage": "combined", "url": ev.url, "title": ev.title})
                if self.result.solved or self._authenticated(root_ev, parser, body):
                    self.result.authenticated = True
                    self.result.credential_username = username
                    self.result.notes.append(f"default credential accepted for username={username}")
                    return parser
            return None

        for username in _usernames():
            body, parser, user_ev = self._request("POST", login.action, self._login_payload(login, username, ""))
            password_form = _password_form(parser.forms)
            self.result.auth_transitions.append({
                "username": username,
                "stage": "username",
                "url": user_ev.url,
                "title": user_ev.title,
                "password_form": bool(password_form),
            })
            if self.result.solved:
                self.result.authenticated = True
                self.result.credential_username = username
                return parser
            if password_form is None:
                continue
            self.result.notes.append(f"username transition discovered for {username}")
            for password in _passwords_for(username):
                pbody, pparser, pev = self._request(
                    "POST", password_form.action, self._login_payload(password_form, username, password)
                )
                self.result.auth_transitions.append({
                    "username": username,
                    "stage": "password",
                    "url": pev.url,
                    "title": pev.title,
                    "password_length": len(password),
                })
                if self.result.solved or self._authenticated(user_ev, pparser, pbody):
                    self.result.authenticated = True
                    self.result.credential_username = username
                    self.result.notes.append(f"default credential accepted for username={username}")
                    return pparser
        return None

    @staticmethod
    def _numeric_mutations(url: str) -> tuple[str, ...]:
        parsed = urllib.parse.urlparse(url)
        candidates: set[str] = set()
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for key, values in query.items():
            for value in values:
                if re.fullmatch(r"\d{1,10}", value):
                    n = int(value)
                    for alt in {max(0, n - 1), n + 1, n + 2, 0, 1, 2}:
                        if alt == n:
                            continue
                        q2 = {k: list(v) for k, v in query.items()}
                        q2[key] = [str(alt)]
                        candidates.add(urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q2, doseq=True))))
        segments = parsed.path.split("/")
        for idx, segment in enumerate(segments):
            if re.fullmatch(r"\d{1,10}", segment):
                n = int(segment)
                for alt in {max(0, n - 1), n + 1, n + 2, 0, 1, 2}:
                    if alt == n:
                        continue
                    s2 = list(segments)
                    s2[idx] = str(alt)
                    candidates.add(urllib.parse.urlunparse(parsed._replace(path="/".join(s2))))
        return tuple(sorted(candidates))

    @staticmethod
    def _get_form_urls(forms: Iterable[Form]) -> tuple[str, ...]:
        urls: set[str] = set()
        for form in forms:
            if form.method != "GET":
                continue
            values = form.value_map()
            query = {k: v for k, v in values.items() if k}
            parsed = urllib.parse.urlparse(form.action)
            if query:
                existing = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                for key, value in query.items():
                    existing[key] = [value]
                url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(existing, doseq=True)))
            else:
                url = form.action
            urls.add(url)
        return tuple(sorted(urls))

    def _contextual_object_urls(self, page_url: str, body: str) -> tuple[str, ...]:
        """Infer a small route family from an observed resource page and its IDs.

        This is a lab-only hypothesis generator: it never runs against non-loopback
        hosts, and it is bounded to two observed IDs and a tiny set of conventional
        REST/query shapes. The candidate must still be fetched and validated.
        """
        ids = []
        for raw in _ID_CONTEXT.findall(body):
            if raw not in ids and int(raw) >= 100:
                ids.append(raw)
        if not ids:
            return ()
        parsed = urllib.parse.urlparse(page_url)
        leaf = (parsed.path.rstrip("/").split("/")[-1] or "").lower()
        if leaf not in {"orders", "order", "trades", "trade", "accounts", "account", "users", "user"}:
            return ()
        singular = leaf[:-1] if leaf.endswith("s") else leaf
        plural = singular + "s"
        origin = f"{parsed.scheme}://{parsed.netloc}"
        urls: set[str] = set()
        for oid in ids[:2]:
            for path in (
                f"/{plural}/{oid}", f"/{singular}/{oid}",
                f"/{plural}/view/{oid}", f"/{singular}/view/{oid}",
            ):
                urls.add(origin + path)
            for path in (f"/{plural}", f"/{singular}"):
                for key in ("id", f"{singular}_id"):
                    urls.add(origin + path + "?" + urllib.parse.urlencode({key: oid}))
        return tuple(sorted(urls))

    def solve(self) -> LabSolveResult:
        _, root_parser, root_ev = self._request("GET", self.target)
        self.result.pages += 1
        self.result.root_forms = [
            {"action": f.action, "method": f.method, "fields": list(f.fields), "values": list(f.values)}
            for f in root_parser.forms
        ]
        if self.result.solved:
            return self.result

        login = _user_form(root_parser.forms)
        seed_parser = root_parser
        if login:
            authenticated_parser = self._authenticate(login, root_ev)
            if authenticated_parser is None:
                self.result.notes.append("default credential corpus did not authenticate")
                return self.result
            seed_parser = authenticated_parser

        queue: list[str] = []
        seen: set[str] = {self.target}
        for link in [*seed_parser.links, *self._get_form_urls(seed_parser.forms)]:
            if _same_origin(self.target, link):
                queue.append(link)

        _, parser, _ = self._request("GET", self.target)
        if self.result.solved:
            return self.result
        for link in [*parser.links, *self._get_form_urls(parser.forms)]:
            if _same_origin(self.target, link):
                queue.append(link)

        while queue and self.result.requests < self.max_requests:
            url = queue.pop(0)
            if url in seen or not _same_origin(self.target, url):
                continue
            seen.add(url)
            body, parser, _ = self._request("GET", url)
            self.result.pages += 1
            if self.result.solved:
                return self.result
            for child in [
                *parser.links,
                *self._get_form_urls(parser.forms),
                *self._contextual_object_urls(url, body),
            ]:
                if _same_origin(self.target, child) and child not in seen:
                    queue.append(child)
            for mutated in self._numeric_mutations(url):
                if self.result.requests >= self.max_requests:
                    break
                self.result.id_mutations += 1
                mbody, _, _ = self._request("GET", mutated)
                if self.result.solved:
                    self.result.notes.append(f"flag reached by numeric object mutation from {url}")
                    return self.result
                if mbody != body and mutated not in seen:
                    queue.append(mutated)

        if not self.result.solved:
            self.result.notes.append("bounded local exploration completed without flag")
        return self.result
