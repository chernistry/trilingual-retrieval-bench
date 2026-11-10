#!/usr/bin/env python3
"""Deterministic pseudonymisation of text trees, with neutral document aliases.

Two layers, both deterministic:

1. **Identifier substitution** over the text. Every identifying token that the
   rules or the denylist name is replaced by a stable pseudonym: the same input
   token maps to the same pseudonym on every run and in every document, so a
   reader following ``<HOST_3>`` across two notes is still following one
   machine.

2. **Path aliasing.** The path of a source document can identify its subject just
   as well as its text. Every source document therefore gets a neutral alias,
   keyed by HMAC under a local salt, reversible only through a mapping file
   that lives outside the output.

What this module does NOT do
----------------------------
It does not detect every identifier. It replaces what the harvest rules and the
denylist name; anything else passes through unchanged.

It does not inspect documents for credentials, and it does not decide whether
a document may be published. A document is refused only when a denylist term
survives substitution.

Nothing here opens a network socket.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import unicodedata
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Where the private state lives
# ---------------------------------------------------------------------------
#
# The salt and the mapping file are the de-anonymisation key: output plus map
# re-identifies every document, so the two must not travel together. The state
# directory defaults to `~/.config/text-scrubber/` and can be moved with the
# `SCRUBBER_DIR` environment variable. The `scrub` command refuses to run when
# the state directory sits inside the output directory.

SCRUB_DIR = Path(os.environ.get("SCRUBBER_DIR", str(Path.home() / ".config" / "text-scrubber")))
SALT_FILE_NAME = "salt"
MAP_FILE_NAME = "map.json"
DENYLIST_FILE_NAME = "denylist.json"

PROSE_SUFFIXES = {".md", ".markdown", ".txt", ".rst", ".org", ".adoc"}

# Directory names skipped at any depth: caches, dependency trees, VCS data.
SKIP_DIRS = {
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", ".nox", ".eggs", ".cache", "dist",
    "build", "target", "site-packages", ".idea", ".vscode", "worktrees",
}
SKIP_DIR_RE = re.compile(r".+[-_]worktrees$|\.egg-info$")

HEADING = re.compile(r"^(#{1,6})\s+(.*\S)\s*$")


class Refused(RuntimeError):
    """A root, or a document, that must not be processed."""


def _assert_outside(state: Path, out: Path) -> None:
    """The mapping file must not be written into the scrubbed output."""
    s, o = state.expanduser().resolve(), out.expanduser().resolve()
    if s == o or o in s.parents:
        raise Refused(
            f"scrub state {s} is inside the output directory {o}; "
            f"set SCRUBBER_DIR elsewhere."
        )


# ---------------------------------------------------------------------------
# Salt
# ---------------------------------------------------------------------------


def salt_path() -> Path:
    return SCRUB_DIR.expanduser() / SALT_FILE_NAME


def load_salt(create: bool = True) -> bytes:
    """32 bytes of local secret. Never printed; report sha256(salt)[:12]."""
    p = salt_path()
    if p.exists():
        raw = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(raw)
    if not create:
        raise Refused(f"no salt at {p}")
    p.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_bytes(32)
    p.write_text(value.hex() + "\n", encoding="utf-8")
    os.chmod(p, 0o600)
    return value


def fingerprint(value: str | bytes) -> str:
    """The only form in which a secret may appear in a report or a log."""
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.sha256(value).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------
#
# One namespace per category so a reader can tell a machine from a person
# without a lookup. The numbering is per namespace.

NAMESPACE = {
    "org": "ORG",
    "product": "PRODUCT",
    "repo": "REPO",
    "pkg": "PKG",
    "person": "PERSON",
    "handle": "USER",
    "email": "EMAIL",
    "domain": "DOMAIN",
    "host": "HOST",
    "ticket": "TICKET",
    "workspace": "WORKSPACE",
    "ip": "IP",
    "customer": "CUSTOMER",
    "term": "TERM",
}

# Categories whose members are structural facts (a directory name, a git author,
# a package name, an address matched by regex). They enter the denylist at a
# single observation; the frequency floor applies only to `term`.
STRUCTURAL = {
    "org", "product", "repo", "pkg", "person", "handle", "email",
    "domain", "host", "ticket", "workspace", "ip",
}

# Categories large enough that third-party noise in them measurably damages the
# text, so the neutral-corpus subtraction is applied. `org`, `person`, `email`,
# `ticket`, `ip`, `repo`, `pkg` and `handle` are left fully denied: they are
# small, and a false positive there costs one pseudonym in the prose, whereas a
# false negative costs an identity.
BACKGROUND_PRUNED = {"term", "domain", "host"}

# ---------------------------------------------------------------------------
# Harvest patterns
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?\.[A-Za-z]{2,24}\b")

URL_HOST_RE = re.compile(r"\b(?:https?|ssh|git|postgres(?:ql)?|redis|amqp|mongodb)://(?:[^/@\s]*@)?([A-Za-z0-9.\-]+)")

# A DNS name is only accepted when the last label is a real TLD or one of the
# internal suffixes people actually use. Without the allowlist `README.md`,
# `package.json` and `v1.2.3` all read as hostnames.
PUBLIC_TLD = {
    "com", "net", "org", "io", "ai", "co", "dev", "app", "cloud", "sh", "run",
    "me", "tech", "xyz", "info", "biz", "us", "uk", "de", "fr", "nl", "il",
    "ru", "eu", "ca", "au", "in", "jp", "se", "ch", "es", "it", "pl", "cz",
    "gov", "edu", "mil", "int", "tv", "cc", "li", "ly", "gg", "to", "st",
    "example",   # reserved for documentation (RFC 2606)
}
INTERNAL_TLD = {"internal", "local", "lan", "intranet", "corp", "svc", "cluster", "test", "localdomain"}
DNS_RE = re.compile(r"\b((?:[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?\.){1,6}([A-Za-z]{2,24}))\b")

# A *bare* DNS-shaped string in text is far more often a method call or an
# attribute chain than a hostname: in a sample of notes, the full TLD
# list turned `log.info`, `crawler.run`, `config.dev` and `res.app` into
# "domains". Bare strings therefore use this narrower set; a string found
# inside a URL keeps the full list, because the scheme settles the question.
BARE_TLD = PUBLIC_TLD - {
    "info", "run", "app", "dev", "sh", "me", "co", "to", "in", "it", "st",
    "cc", "tv", "ly", "gg", "us", "biz", "ai", "se", "es", "pl", "cz", "ca",
}

# `ABC-1234`. The prefix is the identifying half.
TICKET_RE = re.compile(r"\b([A-Z][A-Z0-9]{1,9})-(\d{1,6})\b")

# Prefixes that look like a tracker key and are not one.
TICKET_STOP = {
    "RFC", "CVE", "CWE", "CAPEC", "ISO", "IEC", "IEEE", "NIST", "OWASP", "PCI",
    "GDPR", "SOC", "HIPAA", "FIPS", "ANSI", "ITU", "SHA", "MD", "UTF", "ASCII",
    "HTTP", "HTTPS", "TCP", "UDP", "TLS", "SSL", "SSH", "JWT", "OAUTH", "SAML",
    "API", "SQL", "CSS", "HTML", "JSON", "YAML", "XML", "CSV", "PDF", "PNG",
    "JPEG", "GIF", "SVG", "AWS", "GCP", "IAM", "VPC", "EC", "ECS", "EKS", "S",
    "RDS", "SNS", "SQS", "CI", "CD", "PR", "MR", "UTC", "GMT", "EST", "PST",
    "USD", "EUR", "ILS", "GBP", "RGB", "UUID", "ULID", "GPU", "CPU", "RAM",
    "SSD", "IPV", "IPv", "MAC", "DNS", "DHCP", "NTP", "LDAP", "SMTP", "IMAP",
    "GPT", "LLM", "RAG", "ETL", "KPI", "SLA", "SLO", "SLI", "OKR", "ADR",
    "PYTHON", "NODE", "GO", "V", "X", "Y", "Z", "N", "A", "B", "C", "D", "E",
    "FIG", "TABLE", "EQ", "SEC", "APP", "CH", "P", "Q", "R", "T", "US", "EU",
    "TODO", "FIXME", "WIP", "NA", "TBD", "AKA", "IE", "EG", "ETC", "MIT",
    "BSD", "GPL", "LGPL", "APACHE", "EPOCH", "ID", "PID", "UID", "GID",
    "PART", "STEP", "PHASE", "DAY", "WEEK", "Q1", "Q2", "Q3", "Q4", "H1", "H2",
    "SPF", "DKIM", "DMARC", "CORS", "CSRF", "XSS", "SSRF", "RCE", "DOS",
    "ARM", "X86", "AMD", "INTEL", "NVIDIA", "SDK", "CLI", "GUI", "TUI", "IDE",
}

WORKSPACE_RE = re.compile(
    r"\b([A-Za-z0-9][A-Za-z0-9\-]{1,40})\.(slack\.com|atlassian\.net|atlassian\.com|"
    r"monday\.com|notion\.site|zendesk\.com|freshdesk\.com|pagerduty\.com|"
    r"okta\.com|onelogin\.com|myshopify\.com|lightning\.force\.com|sharepoint\.com)\b",
    re.I,
)

LEGAL_RE = re.compile(
    r"\b((?:[A-Z][A-Za-z0-9&.\-]*)(?:\s+[A-Z][A-Za-z0-9&.\-]*){0,3})\s+"
    r"(Ltd\.?|Limited|Inc\.?|LLC|L\.L\.C\.|GmbH|B\.V\.|BV|N\.V\.|S\.A\.|SAS|"
    r"Corp\.?|Corporation|Company|Technologies|Technology|Systems|Software|"
    r"Solutions|Labs|Laboratories|Group|Holdings|Ventures|Partners)\b"
)

IPV4_RE = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b")

CAP_TOKEN_RE = re.compile(r"\b([A-Z][A-Za-z0-9]{2,23})\b")

# `@handle`. A dot is refused because `@router.handler` and `@app.route` are
# decorators, and a line-initial `@` is refused for the same reason: in a
# sample of notes, decorators were most of the top "handles".
MENTION_RE = re.compile(r"(?<![A-Za-z0-9._%+\-])@([A-Za-z0-9][A-Za-z0-9\-_]{1,38})(?![A-Za-z0-9._\-])")
DECORATOR_RE = re.compile(r"^\s*@")

# Internal-looking machine names: `foo-prod`, `bar-staging-2`, `svc-baz`.
ENVISH_HOST_RE = re.compile(
    r"\b([a-z][a-z0-9]{1,30}(?:-[a-z0-9]{1,20}){0,3}-(?:prod|production|stg|staging|dev|qa|uat|sandbox|preprod|canary))\b"
)

# `a.b.svc.cluster.local`, `foo.internal`
K8S_RE = re.compile(r"\b([a-z0-9\-]{2,40}(?:\.[a-z0-9\-]{2,40})*\.(?:svc|internal|local|cluster\.local))\b")

# Words that are ordinary technical vocabulary and are never the identifying
# part of anything, however often they are capitalised in these trees. Kept
# short on purpose: everything else is decided by the dictionary test plus the
# frequency floor, so this list does not become a hand-written denylist.
TECH_STOP = {
    "python", "javascript", "typescript", "java", "golang", "rust", "ruby",
    "docker", "dockerfile", "kubernetes", "helm", "terraform", "ansible",
    "github", "gitlab", "bitbucket", "jira", "confluence", "slack", "notion",
    "linear", "asana", "trello", "figma", "postgres", "postgresql", "mysql",
    "mariadb", "sqlite", "redis", "mongodb", "elasticsearch", "opensearch",
    "kafka", "rabbitmq", "nginx", "apache", "caddy", "envoy", "traefik",
    "linux", "ubuntu", "debian", "centos", "alpine", "macos", "windows",
    "react", "vue", "angular", "svelte", "next", "nuxt", "django", "flask",
    "fastapi", "express", "spring", "rails", "laravel", "symfony", "node",
    "npm", "yarn", "pnpm", "pip", "poetry", "pytest", "jest", "mocha",
    "eslint", "prettier", "webpack", "vite", "babel", "rollup", "esbuild",
    "aws", "amazon", "azure", "google", "gcp", "cloudflare", "vercel",
    "netlify", "heroku", "digitalocean", "supabase", "firebase", "stripe",
    "twilio", "sendgrid", "auth", "openai", "anthropic", "claude", "gemini",
    "llama", "mistral", "ollama", "huggingface", "langchain", "pandas",
    "numpy", "pytorch", "tensorflow", "sklearn", "grafana", "prometheus",
    "datadog", "sentry", "splunk", "kibana", "jenkins", "circleci",
    "sonarqube", "snyk", "playwright", "cypress", "selenium", "graphql",
    "grpc", "protobuf", "openapi", "swagger", "oauth", "saml", "oidc",
    "readme", "changelog", "license", "contributing", "makefile", "json",
    "yaml", "toml", "markdown", "html", "css", "sql", "bash", "zsh", "shell",
    "http", "https", "rest", "soap", "tcp", "udp", "dns", "ssl", "tls", "ssh",
    "api", "sdk", "cli", "gui", "ide", "cpu", "gpu", "ram", "ssd", "vpn",
    "true", "false", "null", "none", "todo", "fixme", "note", "warning",
    "error", "info", "debug", "trace", "fatal", "panic",
}


def _ordinary(word: str, dic: set[str]) -> bool:
    """Is this an ordinary word? Plurals count: `/usr/share/dict/words` holds
    `solution` but not `solutions`, and without this `Advanced Solutions Ltd`
    read as a company rather than as two ordinary words."""
    if word in dic:
        return True
    for suffix, cut in (("ies", 3), ("es", 2), ("s", 1)):
        if word.endswith(suffix) and len(word) > cut + 2:
            stem = word[:-cut]
            if stem in dic or (suffix == "ies" and stem + "y" in dic):
                return True
    return False


def _dictionary() -> set[str]:
    """Lowercase ordinary-English words, for the collision test.

    A candidate that is an ordinary word is not dropped — it is marked
    `ambiguous` and substituted only in identifier context. See
    `Scrubber._ambiguous_pattern`.
    """
    global _DICT
    if _DICT is not None:
        return _DICT
    words: set[str] = set()
    for p in (Path("/usr/share/dict/words"), Path("/usr/dict/words")):
        if p.exists():
            try:
                words = {
                    w.strip().lower()
                    for w in p.read_text(encoding="utf-8", errors="replace").splitlines()
                    if len(w.strip()) >= 3
                }
            except OSError:
                words = set()
            break
    _DICT = words | TECH_STOP
    return _DICT


_DICT: set[str] | None = None


# ---------------------------------------------------------------------------
# Denylist
# ---------------------------------------------------------------------------


@dataclass
class Term:
    text: str            # as observed, canonical casing
    category: str
    sources: set[str] = field(default_factory=set)
    count: int = 0
    ambiguous: bool = False

    def key(self) -> str:
        return f"{self.category}:{self.text.lower()}"


@dataclass
class Denylist:
    terms: dict[str, Term] = field(default_factory=dict)
    floor: int = 3
    stats: dict = field(default_factory=dict)
    # Per-`term` document frequencies, filled by `harvest()`: how many
    # documents hold the token, and how many of those also name the root.
    df: dict = field(default_factory=dict)
    root_df: dict = field(default_factory=dict)
    cooccur_min: float = 0.25
    # Harvested, never typed. See `harvest()` for where each comes from.
    allow: set[str] = field(default_factory=set)      # third-party + own identity
    background: set[str] = field(default_factory=set)  # neutral-corpus vocabulary
    # Names no allowlist may cancel: the tree's own directory and repository
    # names. A tree that publishes a package under its own name would
    # otherwise allowlist itself out of its own denylist.
    hard: set[str] = field(default_factory=set)
    paranoid: bool = False

    def add(self, text: str, category: str, source: str, count: int = 1) -> None:
        text = text.strip().strip(".,;:!?()[]{}<>\"'`-_/")
        # Two-character tokens are noise everywhere except a tracker prefix
        # (`PC-1234`): in a sample of notes, the two-char harvest was
        # `if`, `re`, `aa`, `yy`, `WW` — regex debris, not identifiers. One of
        # them (`aa`) also collided with the alias path's hex shard.
        floor_len = 2 if category == "ticket" else 3
        if not text or len(text) < floor_len or len(text) > 72:
            return
        if category not in NAMESPACE:
            raise ValueError(f"unknown category {category!r}")
        t = Term(text=text, category=category)
        cur = self.terms.get(t.key())
        if cur is None:
            cur = t
            self.terms[t.key()] = cur
        cur.sources.add(source)
        cur.count += count

    def is_hard(self, text: str) -> bool:
        """A name that IS the subject: the tree's own directory or repository."""
        low = text.lower()
        return low in self.hard or bool(self.hard & set(re.split(r"[^a-z0-9]+", low)))

    def finalise(self) -> "Denylist":
        """Apply the allowlists, the frequency floor and the collision test.

        Subtraction order, and why each subtraction exists:

        `allow`       a name declared as a dependency in this tree's own
                      package manifests, or the current user's git identity.
                      Scrubbing a public library's name is pure knowledge loss:
                      "we used <PKG_7>'s router" tells a reader nothing, and
                      the library's name identifies nobody.
        `background`  a token that also occurs in a neutral background corpus
                      supplied with `--background` (no material from the
                      scrubbed tree in it). `LLM`, `Users`, `E2E`, `URL` are ordinary
                      vocabulary, not internal system names; so
                      are `nodejs.org`, `arxiv.org` and `shields.io`. This is
                      the discriminator that frequency alone cannot be: an
                      internal name is *specific to the tree*, not frequent in
                      it. Applied to `term`, `domain` and `host` only — the
                      categories big enough for the noise to matter — and never
                      to a name in `hard`.
        `floor`       applies only to `term`; structural categories enter at a
                      single observation.

        `paranoid=True` switches both subtractions off: everything harvested is
        denied. That is the setting to use when a tree's material is more
        sensitive than its knowledge is valuable.
        """
        d = _dictionary()
        keep: dict[str, Term] = {}
        dropped: Counter = Counter()
        for k, t in self.terms.items():
            low = t.text.lower()
            hard = bool(self.hard & set(re.split(r"[^a-z0-9]+", low)))
            if (not hard and not self.paranoid and t.category == "term"
                    and any(a in low for a in self.allow if len(a) >= 5)):
                dropped["term:embeds-dependency-name"] += 1
                continue
            if not hard and not self.paranoid and (
                low in self.allow
                or _registrable(low) in self.allow
                or low.split(".")[0] in self.allow
            ):
                dropped[f"{t.category}:third-party-or-self"] += 1
                continue
            t.ambiguous = _ordinary(low, d) or (
                # a multi-word phrase is ambiguous if every word is ordinary
                " " in low and all(_ordinary(w, d) for w in low.split())
            )
            # An ordinary English word needs structural corroboration before it
            # counts as an identifier. Uncorroborated, it is an artefact of the
            # harvest, and substituting it damages the text for nothing:
            #   `data.team@…` split into "persons" `data`, `team`; and
            #   `Data/observability` in a heading then became `<PERSON_2>/observability`;
            #   `Advanced Solutions` / `Senior VP` in prose became "orgs".
            # Corroboration means a source other than free prose or an email
            # local part: a directory name, a repository, a manifest, a git
            # author line, a DNS label.
            # `ticket` is exempt: the substitution only ever fires on the
            # reference form `PREFIX-1234`, which is itself the corroboration.
            # Without this exemption `POLICY-101` and `RISK-3` survived,
            # because `policy` and `risk` are ordinary words.
            if t.ambiguous and not hard and t.category != "ticket":
                corroborated = any(
                    not (src.startswith(("prose", "cap-freq")) or "email-local" in src)
                    for src in t.sources
                )
                if not corroborated:
                    dropped[f"{t.category}:ordinary-word-uncorroborated"] += 1
                    continue
            if not hard and not self.paranoid and t.category in BACKGROUND_PRUNED:
                probe = low.split(".")[0] if "." in low else low
                if probe in self.background and low not in self.hard:
                    dropped[f"{t.category}:in-neutral-corpus"] += 1
                    continue
            if t.category in STRUCTURAL:
                keep[k] = t
                continue
            if t.count < self.floor:
                dropped[f"{t.category}:below-floor"] += 1
                continue
            # Co-occurrence gate. An internal system name turns up in documents
            # that also name the root; a public library's class name in a
            # vendored copy of that library's documentation does not. In a
            # sample of notes, this is what separates `LibraryClassName`
            # (0.00) from a real internal name.
            df = self.df.get(low, 0)
            if df and not self.paranoid:
                share = self.root_df.get(low, 0) / df
                if share < self.cooccur_min:
                    dropped[f"{t.category}:not-co-located-with-root"] += 1
                    continue
            keep[k] = t
        self.terms = keep
        self.stats["dropped"] = dict(dropped)
        self.stats["floor"] = self.floor
        self.stats["by_category"] = dict(Counter(t.category for t in keep.values()))
        self.stats["ambiguous"] = sum(1 for t in keep.values() if t.ambiguous)
        return self

    def to_json(self) -> dict:
        return {
            "version": 1,
            "floor": self.floor,
            "hard": sorted(self.hard),
            "stats": self.stats,
            "terms": [
                {
                    "text": t.text,
                    "category": t.category,
                    "count": t.count,
                    "ambiguous": t.ambiguous,
                    "df": self.df.get(t.text.lower(), 0),
                    "root_df": self.root_df.get(t.text.lower(), 0),
                    "sources": sorted(t.sources),
                }
                for t in sorted(self.terms.values(), key=lambda x: (x.category, x.text.lower()))
            ],
        }

    @classmethod
    def from_json(cls, blob: dict) -> "Denylist":
        d = cls(floor=int(blob.get("floor", 3)), stats=blob.get("stats", {}))
        d.hard = set(blob.get("hard", []))
        for row in blob.get("terms", []):
            t = Term(
                text=row["text"],
                category=row["category"],
                count=int(row.get("count", 0)),
                ambiguous=bool(row.get("ambiguous", False)),
                sources=set(row.get("sources", [])),
            )
            d.terms[t.key()] = t
        return d


# ---------------------------------------------------------------------------
# Harvesting
# ---------------------------------------------------------------------------

MANIFEST_READERS = {
    "package.json": ("json", ("name",)),
    "composer.json": ("json", ("name",)),
    "pyproject.toml": ("toml-name", ()),
    "Cargo.toml": ("toml-name", ()),
    "setup.cfg": ("ini-name", ()),
    "go.mod": ("go", ()),
}

WALK_SKIP_DIRS = SKIP_DIRS | {".scannerwork", "storage", "assets"}


def guard_root(root: Path) -> Path:
    """Resolve a root and refuse one that does not exist."""
    p = Path(root).expanduser().resolve()
    if not p.exists():
        raise Refused(f"no such root: {p}")
    return p


def iter_docs(root: Path, suffixes: set[str] | None = None):
    """Prose documents under `root`, skipping caches and vendored trees."""
    sfx = suffixes if suffixes is not None else PROSE_SUFFIXES
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [
            d for d in dirnames
            if d not in WALK_SKIP_DIRS and not SKIP_DIR_RE.match(d)
        ]
        for name in filenames:
            p = Path(dirpath) / name
            if p.suffix.lower() in sfx:
                yield p


def _read(p: Path, limit: int = 2 * 1024 * 1024) -> str:
    try:
        if p.stat().st_size > limit:
            return ""
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _git_names(root: Path, d: Denylist) -> None:
    """Authors, committers and remotes, read from `.git` as files.

    `git log` is not shelled out to: a bare read of the config plus the
    packed-refs is enough for remotes, and the author list comes from
    `.git/logs/HEAD`, which records every local commit's author line.
    """
    gitdir = root / ".git"
    if not gitdir.is_dir():
        return
    cfg = _read(gitdir / "config")
    for m in re.finditer(r"url\s*=\s*(\S+)", cfg):
        url = m.group(1).strip()
        for host in URL_HOST_RE.findall(url):
            _add_dns(host, d, "git-remote", category_hint="domain")
        # `git@github.com:org/repo.git` and `https://host/org/repo.git`
        m2 = re.search(r"[:/]([A-Za-z0-9._\-]+)/([A-Za-z0-9._\-]+?)(?:\.git)?$", url)
        if m2:
            d.add(m2.group(1), "org", "git-remote")
            d.add(m2.group(2), "repo", "git-remote")
    for m in re.finditer(r"(?:name|email)\s*=\s*(.+)", cfg):
        val = m.group(1).strip()
        if "@" in val and EMAIL_RE.search(val):
            _add_email(val, d, "git-config")
        elif val:
            d.add(val, "person", "git-config")
    head = _read(gitdir / "logs" / "HEAD", limit=8 * 1024 * 1024)
    for line in head.splitlines():
        m = re.match(r"^[0-9a-f]{40} [0-9a-f]{40} (.+?) <([^>]*)> \d+", line)
        if not m:
            continue
        d.add(m.group(1), "person", "git-reflog")
        if m.group(2):
            _add_email(m.group(2), d, "git-reflog")


def _add_email(raw: str, d: Denylist, source: str) -> None:
    for m in EMAIL_RE.finditer(raw):
        addr = m.group(0)
        d.add(addr, "email", source)
        local, _, host = addr.partition("@")
        _add_dns(host, d, source, category_hint="domain")
        # `jane.doe` -> the two name parts; a bare `info`/`support` is not
        # a person, so single ordinary words are left to the dictionary test.
        parts = [x for x in re.split(r"[._\-+]", local) if len(x) >= 3]
        if len(parts) >= 2:
            for x in parts:
                d.add(x, "person", f"{source}:email-local")
        d.add(local, "handle", f"{source}:email-local")


PUBLIC_DOMAIN_STOP = {
    "github.com", "gitlab.com", "bitbucket.org", "google.com", "gmail.com",
    "googlemail.com", "microsoft.com", "outlook.com", "hotmail.com",
    "office.com", "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
    "cloudflare.com", "npmjs.com", "npmjs.org", "pypi.org", "python.org",
    "docker.com", "docker.io", "kubernetes.io", "readthedocs.io", "example.com",
    "example.org", "example.net", "localhost", "wikipedia.org", "stackoverflow.com",
    "medium.com", "dev.to", "youtube.com", "linkedin.com", "twitter.com", "x.com",
    "slack.com", "atlassian.net", "atlassian.com", "notion.so", "figma.com",
    "openai.com", "anthropic.com", "w3.org", "ietf.org", "mozilla.org",
    "letsencrypt.org", "sentry.io", "datadoghq.com", "grafana.com", "jsdelivr.net",
    "unpkg.com", "cdnjs.cloudflare.com", "fonts.googleapis.com", "schema.org",
}


def _registrable(host: str) -> str:
    labels = host.strip(".").lower().split(".")
    if len(labels) >= 3 and labels[-2] in {"co", "com", "org", "net", "ac", "gov"} and len(labels[-1]) == 2:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _add_dns(host: str, d: Denylist, source: str, category_hint: str = "host",
             bare: bool = False) -> None:
    host = host.strip().strip(".").lower()
    if not host or host in {"localhost"} or IPV4_RE.fullmatch(host):
        return
    labels = host.split(".")
    if len(labels) < 2:
        return
    tld = labels[-1]
    allowed = BARE_TLD if bare else PUBLIC_TLD
    if tld not in allowed and tld not in INTERNAL_TLD:
        return
    reg = _registrable(host)
    if reg in PUBLIC_DOMAIN_STOP:
        # A public service's own hostname identifies nobody. Its subdomain can:
        # `team.slack.com` is handled by WORKSPACE_RE, not here.
        return
    if tld in INTERNAL_TLD:
        d.add(host, "host", source)
        d.add(labels[0], "host", f"{source}:label")
        return
    d.add(reg, "domain", source)
    if host != reg:
        d.add(host, "host", source)
    # The registrable name's own second-level label is the identifying word.
    d.add(reg.split(".")[0], category_hint if category_hint != "domain" else "org", f"{source}:label")


def _manifest_names(p: Path, d: Denylist) -> None:
    kind = MANIFEST_READERS.get(p.name)
    if not kind:
        return
    raw = _read(p, limit=512 * 1024)
    if not raw:
        return
    how = kind[0]
    if how == "json":
        try:
            blob = json.loads(raw)
        except ValueError:
            return
        name = blob.get("name")
        if isinstance(name, str) and name:
            scope, _, tail = name.partition("/")
            if tail:
                d.add(scope.lstrip("@"), "org", f"manifest:{p.name}")
                d.add(tail, "pkg", f"manifest:{p.name}")
            else:
                d.add(name, "pkg", f"manifest:{p.name}")
        for key in ("author", "homepage", "repository"):
            val = blob.get(key)
            if isinstance(val, str):
                _harvest_line(val, d, f"manifest:{p.name}")
            elif isinstance(val, dict):
                for v in val.values():
                    if isinstance(v, str):
                        _harvest_line(v, d, f"manifest:{p.name}")
    elif how == "toml-name":
        m = re.search(r'^\s*name\s*=\s*["\']([^"\']+)["\']', raw, re.M)
        if m:
            d.add(m.group(1), "pkg", f"manifest:{p.name}")
    elif how == "ini-name":
        m = re.search(r"^\s*name\s*=\s*(\S+)", raw, re.M)
        if m:
            d.add(m.group(1), "pkg", f"manifest:{p.name}")
    elif how == "go":
        m = re.search(r"^module\s+(\S+)", raw, re.M)
        if m:
            mod = m.group(1)
            parts = mod.split("/")
            if "." in parts[0]:
                _add_dns(parts[0], d, f"manifest:{p.name}", category_hint="domain")
            for part in parts[1:]:
                d.add(part, "pkg", f"manifest:{p.name}")


DEP_FILES = {
    "package.json", "package-lock.json", "pyproject.toml", "requirements.txt",
    "requirements-dev.txt", "Cargo.toml", "go.mod", "composer.json", "Gemfile",
    "pom.xml", "build.gradle", "environment.yml", "Pipfile",
}

DEP_LINE_RE = re.compile(r"^\s*[\"']?([A-Za-z0-9@][A-Za-z0-9._/@\-]{1,60})[\"']?\s*[=><~^:]")
GO_REQUIRE_RE = re.compile(r"^\s+([a-z0-9.\-]+/[A-Za-z0-9./\-]+)\s+v", re.M)


def _dependency_allowlist(root: Path) -> set[str]:
    """Names this tree declares as third-party dependencies.

    A dependency's name is public and identifies nobody, and replacing it
    destroys the technical content of the note that mentions it. The list is
    read out of the tree's own manifests, so it is harvested like everything
    else here — the module hard-codes no vendor names.
    """
    allow: set[str] = set()

    def _flat(name: str) -> None:
        name = name.strip().strip("\"'").lower()
        if not name or len(name) < 2:
            return
        allow.add(name)
        if name.startswith("@") and "/" in name:
            scope, _, tail = name[1:].partition("/")
            allow.add(scope)
            allow.add(tail)
        for part in re.split(r"[/@]", name):
            if len(part) >= 3:
                allow.add(part)
        # `examplelib` -> also its documentation domain `examplelib.dev`
        head = re.split(r"[/@\-]", name.lstrip("@"))[0]
        if len(head) >= 3:
            allow.add(head)

    for name in DEP_FILES:
        for p in list(root.rglob(name))[:300]:
            if any(part in WALK_SKIP_DIRS for part in p.parts):
                continue
            raw = _read(p, limit=4 * 1024 * 1024)
            if not raw:
                continue
            if p.name.endswith(".json"):
                try:
                    blob = json.loads(raw)
                except ValueError:
                    continue
                for key in ("dependencies", "devDependencies", "peerDependencies",
                            "optionalDependencies", "require", "require-dev", "packages"):
                    node = blob.get(key)
                    if isinstance(node, dict):
                        for dep in node:
                            _flat(dep.lstrip("node_modules/"))
            elif p.name == "go.mod":
                for m in GO_REQUIRE_RE.finditer(raw):
                    _flat(m.group(1))
            else:
                for line in raw.splitlines():
                    if line.lstrip().startswith("#"):
                        continue
                    m = DEP_LINE_RE.match(line)
                    if m:
                        _flat(m.group(1))
                    elif re.match(r"^[A-Za-z0-9][A-Za-z0-9._\-]{1,60}$", line.strip()):
                        _flat(line.strip())
    return allow


def _self_allowlist() -> set[str]:
    """The current user's own identity, read from the local git config.

    The user is not the subject. Replacing their own name and handles makes every
    note read as if a stranger wrote it, and hides nobody. Read, not
    typed: `~/.gitconfig` is the source.
    """
    allow: set[str] = set()
    for cfg in (Path.home() / ".gitconfig", Path.home() / ".config" / "git" / "config"):
        raw = _read(cfg, limit=256 * 1024)
        for m in re.finditer(r"^\s*(?:name|email|user)\s*=\s*(.+)$", raw, re.M):
            val = m.group(1).strip()
            for m2 in EMAIL_RE.finditer(val):
                addr = m2.group(0).lower()
                allow.add(addr)
                local = addr.split("@")[0]
                allow.add(local)
                for part in re.split(r"[._\-+]", local):
                    if len(part) >= 3:
                        allow.add(part)
            parts = [x for x in re.split(r"[\s._\-]+", val.lower())
                     if len(x) >= 3 and "@" not in x]
            allow.update(parts)
            if len(parts) >= 2:
                # `Jane Doe` also writes herself `janedoe`
                allow.add("".join(parts))
                allow.add("".join(reversed(parts)))
    return allow


# `Domain Name System (DNS)` / `DNS (Domain Name System)`. An acronym the
# document itself expands is standard vocabulary of the field, not an internal
# name: nobody glosses their own internal system for their own team.
GLOSS_A = re.compile(r"\b((?:[A-Z][A-Za-z]+[ \-]){1,6}[A-Z][A-Za-z]+)\s*\(([A-Z]{2,8})s?\)")
GLOSS_B = re.compile(r"\b([A-Z]{2,8})s?\s*\(((?:[A-Z][A-Za-z]+[ \-]){1,6}[A-Z][A-Za-z]+)\)")


def _glossed_acronyms(text: str) -> set[str]:
    out: set[str] = set()
    for pat, ai, li in ((GLOSS_A, 2, 1), (GLOSS_B, 1, 2)):
        for m in pat.finditer(text):
            acro, long = m.group(ai), m.group(li)
            initials = "".join(w[0] for w in re.split(r"[ \-]+", long) if w)
            if initials.upper().startswith(acro.upper()[:2]) and len(acro) >= 2:
                out.add(acro.lower())
    return out


BG_TOKEN_RE = re.compile(r"\b([A-Za-z][A-Za-z0-9]{2,23})\b")


def background_vocab(roots: list[Path], max_docs: int = 12000) -> set[str]:
    """Lowercased token vocabulary of a corpus that holds no material from the
    scrubbed tree.

    A capitalised token that also lives there is ordinary vocabulary, not an
    internal system name.
    """
    vocab: set[str] = set()
    seen = 0
    for root in roots:
        if not root.exists():
            continue
        for p in iter_docs(root):
            if seen >= max_docs:
                break
            seen += 1
            for tok in BG_TOKEN_RE.findall(_read(p, limit=512 * 1024)):
                vocab.add(tok.lower())
    return vocab


def _harvest_line(line: str, d: Denylist, source: str) -> None:
    """Every regex-derived candidate in one line of text."""
    for m in EMAIL_RE.finditer(line):
        _add_email(m.group(0), d, source)
    for m in WORKSPACE_RE.finditer(line):
        d.add(m.group(1), "workspace", source)
    for host in URL_HOST_RE.findall(line):
        _add_dns(host, d, source)
    for m in K8S_RE.finditer(line):
        d.add(m.group(1), "host", source)
        d.add(m.group(1).split(".")[0], "host", f"{source}:label")
    for m in ENVISH_HOST_RE.finditer(line):
        d.add(m.group(1), "host", source)
    for m in DNS_RE.finditer(line):
        _add_dns(m.group(1), d, source, bare=True)
    for m in TICKET_RE.finditer(line):
        pre = m.group(1)
        if pre.upper() not in TICKET_STOP and not pre.isdigit():
            d.add(pre, "ticket", source)
    for m in LEGAL_RE.finditer(line):
        d.add(m.group(1), "org", source)
    for m in IPV4_RE.finditer(line):
        ip = m.group(1)
        octs = [int(x) for x in ip.split(".") if x.isdigit()]
        if len(octs) != 4 or any(o > 255 for o in octs):
            continue
        # Documentation and well-known addresses identify nobody, and the cloud
        # metadata address is load-bearing technical content.
        if octs[0] in (0, 127, 255) or ip.startswith(("192.0.2.", "198.51.100.", "203.0.113.")):
            continue
        if octs[0] == 169 and octs[1] == 254:
            continue
        if ip in {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}:
            continue
        if all(o < 10 for o in octs):   # `1.2.3.4` is a version far more often
            continue
        d.add(ip, "ip", source)
    if not DECORATOR_RE.match(line):
        for m in MENTION_RE.finditer(line):
            d.add(m.group(1), "handle", source)


def harvest(roots: list[Path], floor: int = 3, max_docs: int | None = None,
            background_roots: list[Path] | None = None,
            paranoid: bool = False) -> Denylist:
    """Derive the denylist from the sources. Nothing is hand-typed here."""
    d = Denylist(floor=floor, paranoid=paranoid)
    caps: Counter = Counter()
    doc_freq: dict[str, int] = {}
    root_freq: dict[str, int] = {}
    seen_docs = 0
    roots = [guard_root(r) for r in roots]

    d.allow |= _self_allowlist()
    for root in roots:
        d.allow |= _dependency_allowlist(root)
    bg_roots = background_roots if background_roots is not None else []
    d.background = background_vocab([Path(b) for b in bg_roots])

    for root in roots:
        # 1. The root's own name and the names of its immediate subtrees. A
        #    directory named after the subject is the single highest-confidence
        #    identifier in the whole tree.
        d.add(root.name, "org", "root-dir")
        d.hard.add(root.name.lower())
        for child in sorted(root.iterdir()) if root.is_dir() else []:
            if child.name.startswith("."):
                continue
            if child.is_dir() and (child / ".git").exists():
                d.add(child.name, "repo", "repo-dir")
                d.hard.add(child.name.lower())

        # 2. git: remotes, authors, committers.
        _git_names(root, d)
        for sub in root.glob("*/.git"):
            _git_names(sub.parent, d)

        # 3. package manifests.
        for name in MANIFEST_READERS:
            for p in list(root.rglob(name))[:400]:
                if any(part in WALK_SKIP_DIRS for part in p.parts):
                    continue
                _manifest_names(p, d)

        # 4. every prose document: regex candidates + capitalised-token counts.
        root_re = re.compile("|".join(re.escape(h) for h in sorted(d.hard)), re.I) \
            if d.hard else None
        for p in iter_docs(root):
            if max_docs is not None and seen_docs >= max_docs:
                break
            seen_docs += 1
            # the file's own path components are candidates too
            for part in p.relative_to(root).parts[:-1]:
                if len(part) >= 3 and not part.startswith("."):
                    caps[part] += 1
            text = _read(p)
            if not text:
                continue
            first = text.lstrip().splitlines()[0] if text.strip() else ""
            m = HEADING.match(first)
            if m:
                for tok in CAP_TOKEN_RE.findall(m.group(2)):
                    caps[tok] += 2      # a README title is a strong signal
            d.allow |= _glossed_acronyms(text)
            here: set[str] = set()
            for line in text.splitlines():
                _harvest_line(line, d, "prose")
                for tok in CAP_TOKEN_RE.findall(line):
                    caps[tok] += 1
                    here.add(tok.lower())
            # Relative to the root: the absolute path always contains the root
            # directory's name, which would make every document "co-located".
            rel = str(p.relative_to(root))
            names_root = bool(root_re and root_re.search(rel))
            if not names_root and root_re:
                names_root = bool(root_re.search(text))
            for tok in here:
                doc_freq[tok] = doc_freq.get(tok, 0) + 1
                if names_root:
                    root_freq[tok] = root_freq.get(tok, 0) + 1

    # 5. High-frequency capitalised tokens that are not ordinary English and
    #    not ordinary technical vocabulary. This is the bucket that catches an
    #    internal system name nobody wrote down anywhere structural.
    d.df = doc_freq
    d.root_df = root_freq
    dic = _dictionary()
    already = {t.text.lower() for t in d.terms.values()}
    for tok, n in caps.items():
        low = tok.lower()
        if low in dic or low in already:
            continue
        if len(low) < 3 or low.isdigit():
            continue
        d.add(tok, "term", f"cap-freq:{n}", count=n)

    d.stats["docs_read"] = seen_docs
    d.stats["cap_tokens_seen"] = len(caps)
    d.stats["cap_tokens_kept_before_floor"] = sum(
        1 for tok in caps if tok.lower() not in dic and tok.lower() not in already
    )
    d.stats["allowlist_size"] = len(d.allow)
    d.stats["hard_deny"] = sorted(d.hard)
    d.stats["paranoid"] = paranoid
    d.stats["background_vocab"] = len(d.background)
    d.stats["candidates_before_subtraction"] = len(d.terms)
    d.stats["roots"] = [str(r) for r in roots]
    return d.finalise()


# ---------------------------------------------------------------------------
# Pseudonym map — the only reverse of both layers
# ---------------------------------------------------------------------------


class PseudonymMap:
    """Append-only assignment of pseudonyms and path aliases.

    Append-only is what makes the pseudonyms stable as the denylist grows: a
    term that already has `HOST_4` keeps it forever, and a new term takes the
    next free number in its namespace. Within one run new terms are assigned in
    sorted order, so two runs against an empty map produce identical output.
    """

    def __init__(self, path: Path | None = None, salt: bytes | None = None):
        self.path = path or (SCRUB_DIR.expanduser() / MAP_FILE_NAME)
        self.salt = salt if salt is not None else load_salt()
        self.terms: dict[str, str] = {}
        self.counters: dict[str, int] = {}
        self.paths: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        blob = json.loads(self.path.read_text(encoding="utf-8"))
        self.terms = dict(blob.get("terms", {}))
        self.counters = {k: int(v) for k, v in blob.get("counters", {}).items()}
        self.paths = dict(blob.get("paths", {}))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        blob = {
            "version": 1,
            "salt_sha256_12": fingerprint(self.salt),
            "terms": self.terms,
            "counters": self.counters,
            "paths": self.paths,
        }
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(blob, ensure_ascii=False, indent=1, sort_keys=True), encoding="utf-8")
        os.replace(tmp, self.path)
        os.chmod(self.path, 0o600)

    # -- layer 1 ----------------------------------------------------------
    def pseudonym(self, category: str, canonical: str) -> str:
        key = f"{category}:{canonical.lower()}"
        got = self.terms.get(key)
        if got:
            return got
        ns = NAMESPACE[category]
        self.counters[ns] = self.counters.get(ns, 0) + 1
        got = f"<{ns}_{self.counters[ns]}>"
        self.terms[key] = got
        return got

    def assign_all(self, deny: Denylist) -> None:
        """Assign in a deterministic order so a fresh map is reproducible."""
        for t in sorted(deny.terms.values(), key=lambda x: (x.category, x.text.lower())):
            self.pseudonym(t.category, t.text)

    # -- layer 2 ----------------------------------------------------------
    def alias_id(self, abspath: str) -> str:
        return hmac.new(self.salt, f"path:{abspath}".encode("utf-8"), hashlib.sha256).hexdigest()[:16]

    def alias(self, abspath: str, safe_stem: str, suffix: str) -> str:
        # No short hex shard in the path: a two-character shard collided with a
        # two-character denylist term (`aa`, a harvested hostname label) and
        # tripped the alias's own identifier check.
        aid = self.alias_id(abspath)
        rel = f"scrubbed/{aid}/{safe_stem}{suffix}"
        rec = self.paths.get(abspath)
        if rec is None:
            self.paths[abspath] = {"alias": rel}
        else:
            rec["alias"] = rel
        return rel

    def reverse_path(self, alias: str) -> str | None:
        for src, rec in self.paths.items():
            if rec.get("alias") == alias:
                return src
        return None


# ---------------------------------------------------------------------------
# Substitution
# ---------------------------------------------------------------------------

# Contexts in which an ordinary English word is being used as a name. The token
# itself is `%s`.
_IDENT_LEFT = r"(?:[/@:.\-_`\"']|\bthe\s+|\bin\s+|\bon\s+|\bvia\s+)"
_IDENT_RIGHT = (
    r"(?:[/@:.\-_`\"']|\s+(?:service|services|system|cluster|pipeline|dashboard|"
    r"repo|repository|API|api|instance|environment|env|team|namespace|DB|db|"
    r"database|queue|topic|bucket|job|worker|agent|module|component|platform)\b)"
)

WORD_CHARS = "A-Za-z0-9_"

# The boundary class for an identifier is letters and digits, NOT `_`.
# With `_` treated as a word character, env-var and snake_case
# tokens of the shape `NAME_API_URL`, `NAME_HMAC_KEY` and `name_errors_2025`
# all survived a scrub whose survivor count read 0 — the oracle shared the
# boundary bug. In an identifier `_` is a separator, so it must end a token.
WORD_EDGE = "A-Za-z0-9"

# Substitution happens into an inert sentinel, not straight into `<ORG_1>`.
# Reason: the pseudonym namespace is a word (`USER`, `HOST`, `ORG`),
# and `user` was itself a denylist term. The ambiguous rule treats `_` as
# identifier context, so `USER` inside `<USER_50>` matched on the next round
# and the text ran away to `<<<<USER_50>_50>_50>_45>`. A sentinel built from
# control characters cannot be matched by any rule here: none of them is in
# `[A-Za-z0-9_]` and none is in the identifier-context classes.
SENTINEL_OPEN = "\x00"
SENTINEL_CLOSE = "\x01"
_DIGIT_OFFSET = 2   # "0".."9" -> \x02..\x0b


def _sentinel(idx: int) -> str:
    body = "".join(chr(_DIGIT_OFFSET + int(c)) for c in str(idx))
    return f"{SENTINEL_OPEN}{body}{SENTINEL_CLOSE}"


PSEUDONYM_RE = re.compile(r"<[A-Z]+_\d+>")

SENTINEL_RE = re.compile(f"{SENTINEL_OPEN}([\\x02-\\x0b]+){SENTINEL_CLOSE}")


def _unsentinel(text: str, table: list[str]) -> str:
    def _one(m: "re.Match[str]") -> str:
        idx = int("".join(str(ord(c) - _DIGIT_OFFSET) for c in m.group(1)))
        return table[idx]
    return SENTINEL_RE.sub(_one, text)


def _hard_pattern(text: str) -> str:
    """The subject's own name: a bare substring, no boundary conditions.

    A plural (`<name>s`) and an env var (`<NAME>_MAX_RESOLUTION`) both survived
    a boundary match. For the two or three names that ARE the subject, mangling
    an unrelated word that happens to contain them is a price worth paying; for
    everything else the boundary form below applies.
    """
    return re.escape(text)


def _boundary_pattern(text: str) -> str:
    """Whole-token match that also fires inside `foo-Bar_baz` compounds.

    `\\b` alone would replace `Zorvex` inside `ZorvexSecure` and leave a half
    identifier behind; that is wanted (the remaining half carries no name), but
    it must not fire inside an unrelated longer word such as `Zorvexism`, so the
    right edge refuses a following letter unless the whole token was consumed.
    """
    esc = re.escape(text)
    return rf"(?<![{WORD_EDGE}]){esc}(?![{WORD_EDGE}])"


@dataclass
class ScrubResult:
    alias: str
    text: str
    replacements: int
    tokens_total: int
    tokens_replaced: int
    refused: bool = False
    reason: str = ""
    findings: list = field(default_factory=list)
    survivors: dict = field(default_factory=dict)


class Scrubber:
    def __init__(self, deny: Denylist, pmap: PseudonymMap, strict: bool = False):
        self.deny = deny
        self.map = pmap
        self.strict = strict
        self.map.assign_all(deny)
        self._ambig: list[tuple[re.Pattern[str], str, str]] = []
        # One alternation per rule class instead of one pass per term. With
        # ~800 terms the per-term form did ~2 400 regex passes over every
        # document; this does four. Alternatives are ordered longest-first, so
        # `beacon-prod.zorvex.example` is consumed before `zorvex`, and a
        # pseudonym inserted by the pass cannot be re-matched inside it.
        self._repl: dict[str, str] = {}
        self._table: list[str] = []
        self._hard: re.Pattern[str] | None = None
        self._exact_ci: re.Pattern[str] | None = None
        self._exact_cs: re.Pattern[str] | None = None
        self._ticket: re.Pattern[str] | None = None
        self._camel: re.Pattern[str] | None = None
        self._compile()

    def _compile(self) -> None:
        ordered = sorted(self.deny.terms.values(), key=lambda t: (-len(t.text), t.text.lower()))
        ci: list[str] = []
        cs: list[str] = []
        tickets: list[str] = []
        camel: list[str] = []
        hard: list[str] = []
        for t in ordered:
            real = self.map.pseudonym(t.category, t.text)
            self._table.append(real)
            repl = _sentinel(len(self._table) - 1)
            self._repl[t.text.lower()] = repl
            if self.deny.is_hard(t.text):
                hard.append(_hard_pattern(t.text))
                continue
            if t.category == "ticket":
                # Only the reference form. In a sample of notes, the
                # bare prefixes were mostly domain vocabulary reused as an enum
                # (`POLICY`, `RISK`, `PLAN`): scrubbing those as words
                # destroys the note and hides no identity, while `PLAN-4412`
                # is a tracker reference and does identify.
                tickets.append(re.escape(t.text))
                continue
            if t.ambiguous and not self.strict:
                body = re.escape(t.text)
                pat = re.compile(
                    rf"(?P<l>{_IDENT_LEFT})(?P<w>{body})(?![{WORD_CHARS}])"
                    rf"|(?<![{WORD_CHARS}])(?P<w2>{body})(?P<r>{_IDENT_RIGHT})",
                    re.I if len(t.text) > 3 else 0,
                )
                self._ambig.append((pat, repl, t.text))
                continue
            (ci if len(t.text) > 3 else cs).append(re.escape(t.text))
            # A CamelCase compound can hide a name: `ZorvexSecureGateway`. Only
            # whole CamelCase segments, so `Navigation` is never split at `Nav`.
            if len(t.text) >= 4 and t.text.isalnum():
                camel.append(re.escape(t.text.capitalize()))

        def _alt(parts: list[str], flags: int = 0) -> re.Pattern[str] | None:
            if not parts:
                return None
            return re.compile(
                rf"(?<![{WORD_EDGE}])(?:{'|'.join(parts)})(?![{WORD_EDGE}])", flags)

        self._hard = re.compile("|".join(hard), re.I) if hard else None
        self._exact_ci = _alt(ci, re.I)
        self._exact_cs = _alt(cs)
        if tickets:
            self._ticket = re.compile(
                rf"(?<![{WORD_CHARS}])(?:{'|'.join(tickets)})-\d{{1,6}}(?![{WORD_CHARS}])")
        if camel:
            self._camel = re.compile(
                rf"(?<=[a-z0-9])(?:{'|'.join(camel)})(?=[A-Z]|\b)"
                rf"|(?:{'|'.join(camel)})(?=[A-Z][a-z])")

    def _lookup(self, m: "re.Match[str]") -> str:
        got = m.group(0).lower()
        return self._repl.get(got, got)

    def _lookup_ticket(self, m: "re.Match[str]") -> str:
        head = m.group(0).rsplit("-", 1)[0].lower()
        return self._repl.get(head, m.group(0))

    # -- text -------------------------------------------------------------
    MAX_ROUNDS = 6

    def scrub_text(self, text: str) -> tuple[str, int]:
        """Substitute to a fixed point.

        One pass is not enough: replacing a term inside a compound creates a
        word boundary that exposes its neighbour. Example —
        `request.userData.masterUser` became `request.user<PERSON_2>.master…`,
        and the now-bounded `user` was a denylist term that the single-pass
        version left in the text. Rounds terminate because a pseudonym
        (`<USER_36>`) contains no matchable token: the namespace is followed by
        `_`, which the boundary lookahead refuses.
        """
        n = 0
        # Any pseudonym already in the text — from an earlier scrub of the same
        # document — is parked in a sentinel too, which makes the function
        # idempotent: scrubbing scrubbed text is a no-op instead of nesting
        # `<<USER_1>_1>`.
        table = list(self._table)

        def _park(m: "re.Match[str]") -> str:
            table.append(m.group(0))
            return _sentinel(len(table) - 1)

        text = PSEUDONYM_RE.sub(_park, text)
        for _ in range(self.MAX_ROUNDS):
            round_n = 0
            for pat, fn in ((self._hard, self._lookup),
                            (self._ticket, self._lookup_ticket),
                            (self._exact_cs, self._lookup),
                            (self._exact_ci, self._lookup),
                            (self._camel, self._lookup)):
                if pat is None:
                    continue
                text, k = pat.subn(fn, text)
                round_n += k
            for pat, repl, _orig in self._ambig:
                def _sub(m: re.Match, repl=repl) -> str:
                    if m.group("w") is not None:
                        return f"{m.group('l')}{repl}"
                    return f"{repl}{m.group('r')}"
                text, k = pat.subn(_sub, text)
                round_n += k
            n += round_n
            if not round_n:
                break
        return _unsentinel(text, table), n

    # -- paths ------------------------------------------------------------
    def safe_stem(self, name: str) -> str:
        """A basename with every identifier gone, or `doc` if nothing is left."""
        stem = Path(name).stem
        out, _ = self.scrub_text(stem)
        # Pseudonyms in a filename are noise; drop them and any leftover
        # punctuation runs.
        out = re.sub(r"<[A-Z]+_\d+>", "", out)
        out = unicodedata.normalize("NFKD", out)
        out = re.sub(r"[^A-Za-z0-9._\-]+", "-", out).strip("-._")
        out = re.sub(r"-{2,}", "-", out)
        if not out or len(out) < 2 or self.hits(out):
            return "doc"
        return out[:60]

    def alias_path(self, abspath: str | Path) -> str:
        p = Path(abspath)
        suffix = p.suffix.lower() or ".md"
        alias = self.map.alias(str(p), self.safe_stem(p.name), suffix)
        if self.hits(alias):
            # Never emit an alias that carries an identifier: drop the readable
            # stem entirely rather than ship a re-identifying path.
            alias = self.map.alias(str(p), "doc", suffix)
        if self.hits(alias):
            raise Refused(f"cannot build a clean alias for {fingerprint(str(p))}")
        return alias

    # -- verification -----------------------------------------------------
    def hits(self, text: str) -> dict[str, int]:
        """Denylist terms still literally present. The survivor test.

        Built from the denylist independently of the substitution patterns and
        rebuilt whenever the denylist changes, so a bug in `_compile` shows up
        here instead of being reproduced by it. That independence is the whole
        value of the check: an oracle that shares the code under test proves
        nothing.
        """
        # A pseudonym is not content: `<USER_1>` holds the literal `USER`, and
        # with `_` no longer closing a token the oracle would count it as a
        # survivor of the term `user`. Blank them out first.
        text = PSEUDONYM_RE.sub(" ", text)
        pats = self._oracle()
        out: Counter = Counter()
        for pat, kind in pats:
            for m in pat.finditer(text):
                got = m.group(0)
                low = got.rsplit("-", 1)[0].lower() if kind == "ticket" else got.lower()
                t = self._by_low.get(low)
                out[f"{t.category}:{t.text}" if t else f"?:{got}"] += 1
        return dict(out)

    def _oracle(self) -> list[tuple[re.Pattern[str], str]]:
        stamp = len(self.deny.terms)
        if getattr(self, "_oracle_stamp", None) == stamp:
            return self._oracle_pats
        ci: list[str] = []
        cs: list[str] = []
        tickets: list[str] = []
        hard: list[str] = []
        self._by_low = {}
        for t in sorted(self.deny.terms.values(), key=lambda x: (-len(x.text), x.text.lower())):
            self._by_low[t.text.lower()] = t
            if self.deny.is_hard(t.text):
                hard.append(re.escape(t.text))
                continue
            if t.ambiguous and not self.strict:
                # An ordinary word surviving is expected, not a defect; it is
                # counted separately by `hits_ambiguous`.
                continue
            if t.category == "ticket":
                tickets.append(re.escape(t.text))
                continue
            (ci if len(t.text) > 3 else cs).append(re.escape(t.text))
        pats: list[tuple[re.Pattern[str], str]] = []
        if hard:
            pats.append((re.compile("|".join(hard), re.I), ""))
        if tickets:
            pats.append((re.compile(
                rf"(?<![{WORD_CHARS}])(?:{'|'.join(tickets)})-\d{{1,6}}(?![{WORD_CHARS}])"),
                "ticket"))
        for parts, flags in ((cs, 0), (ci, re.I)):
            if parts:
                pats.append((re.compile(
                    rf"(?<![{WORD_EDGE}])(?:{'|'.join(parts)})(?![{WORD_EDGE}])", flags), ""))
        self._oracle_stamp = stamp
        self._oracle_pats = pats
        return pats

    def hits_ambiguous(self, text: str) -> dict[str, int]:
        text = PSEUDONYM_RE.sub(" ", text)
        out: dict[str, int] = {}
        for t in self.deny.terms.values():
            if not t.ambiguous:
                continue
            n = len(re.findall(_boundary_pattern(t.text), text, re.I if len(t.text) > 3 else 0))
            if n:
                out[f"{t.category}:{t.text}"] = n
        return out


# ---------------------------------------------------------------------------
# Admission
# ---------------------------------------------------------------------------

TOKEN_RE = re.compile(r"[A-Za-z\u0400-\u04ff0-9_]+")


def admissible(scrubber: Scrubber, path: Path, text: str | None = None) -> ScrubResult:
    """Scrub one document and decide whether it may be written.

    A document is refused with reason `survivor` when a denylist term is still
    literally present after substitution. That is a defect in the scrubber, and
    the document is refused rather than written with the identifier in it.
    """
    p = Path(path)
    if text is None:
        text = _read(p)

    scrubbed, n = scrubber.scrub_text(text)
    survivors = scrubber.hits(scrubbed)
    total = len(TOKEN_RE.findall(text))
    replaced = len(re.findall(r"<[A-Z]+_\d+>", scrubbed))
    if survivors:
        return ScrubResult(
            "", "", n, total, replaced, refused=True, reason="survivor",
            survivors=survivors,
        )

    alias = scrubber.alias_path(p)
    return ScrubResult(alias, scrubbed, n, total, replaced)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _cmd_harvest(a) -> int:
    bg = [Path(x) for x in a.background] if getattr(a, "background", None) else None
    deny = harvest([Path(r) for r in a.root], floor=a.floor, max_docs=a.max_docs,
                   background_roots=bg, paranoid=a.paranoid)
    out = Path(a.out) if a.out else SCRUB_DIR / DENYLIST_FILE_NAME
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(deny.to_json(), ensure_ascii=False, indent=1), encoding="utf-8")
    os.chmod(out, 0o600)
    print(json.dumps({"denylist": str(out), "terms": len(deny.terms), **deny.stats},
                     ensure_ascii=False, indent=1))
    return 0


def _load_pair(a) -> tuple[Denylist, Scrubber]:
    dpath = Path(a.denylist) if a.denylist else SCRUB_DIR / DENYLIST_FILE_NAME
    deny = Denylist.from_json(json.loads(dpath.read_text(encoding="utf-8")))
    pmap = PseudonymMap()
    return deny, Scrubber(deny, pmap, strict=getattr(a, "strict", False))


def _cmd_scrub(a) -> int:
    deny, scr = _load_pair(a)
    outdir = Path(a.out)
    _assert_outside(scr.map.path.parent, outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    stats: Counter = Counter()
    rows = []
    for root in [guard_root(Path(r)) for r in a.root]:
        for p in iter_docs(root):
            res = admissible(scr, p)
            if res.refused:
                stats[f"refused:{res.reason}"] += 1
                rows.append({"src_sha12": fingerprint(str(p)), "refused": res.reason,
                             "survivors": sorted(res.survivors)[:5]})
                continue
            stats["written"] += 1
            dest = outdir / res.alias
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(res.text, encoding="utf-8")
            rows.append({
                "alias": res.alias,
                "tokens": res.tokens_total,
                "replaced": res.tokens_replaced,
                "share": round(res.tokens_replaced / res.tokens_total, 4) if res.tokens_total else 0.0,
            })
    scr.map.save()
    (outdir / "_scrub-report.json").write_text(
        json.dumps({"stats": dict(stats), "docs": rows}, ensure_ascii=False, indent=1),
        encoding="utf-8")
    print(json.dumps({"out": str(outdir), **dict(stats),
                      "map": str(scr.map.path), "salt_sha256_12": fingerprint(scr.map.salt)},
                     ensure_ascii=False, indent=1))
    return 0


def _cmd_verify(a) -> int:
    deny, scr = _load_pair(a)
    root = Path(a.scrubbed)
    surv: Counter = Counter()
    ambig: Counter = Counter()
    files = 0
    alias_bad = []
    for p in iter_docs(root, suffixes=None):
        files += 1
        text = _read(p)
        for k, n in scr.hits(text).items():
            surv[k] += n
        if a.include_ambiguous:
            for k, n in scr.hits_ambiguous(text).items():
                ambig[k] += n
        rel = str(p.relative_to(root))
        if scr.hits(rel):
            alias_bad.append(rel)
    print(json.dumps({
        "files": files,
        "survivors_total": sum(surv.values()),
        "survivor_terms": dict(surv.most_common(40)),
        "alias_paths_carrying_identifier": alias_bad[:20],
        "ambiguous_occurrences": sum(ambig.values()),
        "ambiguous_terms": dict(ambig.most_common(40)),
    }, ensure_ascii=False, indent=1))
    return 1 if surv or alias_bad else 0


def _cmd_alias(a) -> int:
    deny, scr = _load_pair(a)
    for one in a.path:
        print(scr.alias_path(one))
    scr.map.save()
    return 0


def _cmd_reverse(a) -> int:
    pmap = PseudonymMap()
    for one in a.alias:
        src = pmap.reverse_path(one)
        print(src if src else f"(not in map) {one}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    h = sub.add_parser("harvest", help="derive the denylist from the sources")
    h.add_argument("--root", action="append", required=True)
    h.add_argument("--floor", type=int, default=3)
    h.add_argument("--max-docs", type=int, default=None, dest="max_docs")
    h.add_argument("--out")
    h.add_argument("--background", action="append", default=None)
    h.add_argument("--paranoid", action="store_true",
                   help="deny everything harvested: no third-party or neutral-corpus subtraction")
    h.set_defaults(fn=_cmd_harvest)

    s = sub.add_parser("scrub", help="write scrubbed derivatives under aliases")
    s.add_argument("--root", action="append", required=True)
    s.add_argument("--out", required=True)
    s.add_argument("--denylist")
    s.add_argument("--strict", action="store_true")
    s.set_defaults(fn=_cmd_scrub)

    v = sub.add_parser("verify", help="survivor count over a scrubbed tree")
    v.add_argument("--scrubbed", required=True)
    v.add_argument("--denylist")
    v.add_argument("--strict", action="store_true")
    v.add_argument("--include-ambiguous", action="store_true")
    v.set_defaults(fn=_cmd_verify)

    al = sub.add_parser("alias", help="print the alias of a source path")
    al.add_argument("path", nargs="+")
    al.add_argument("--denylist")
    al.set_defaults(fn=_cmd_alias)

    rv = sub.add_parser("reverse", help="resolve an alias back through the local map")
    rv.add_argument("alias", nargs="+")
    rv.set_defaults(fn=_cmd_reverse)

    a = ap.parse_args()
    try:
        return a.fn(a)
    except Refused as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
