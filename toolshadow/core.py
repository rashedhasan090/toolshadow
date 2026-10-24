"""Core analysis for toolshadow.

Input is one or more MCP ``tools/list`` dumps, one per server. Each dump is a
JSON object ``{"tools": [...]}`` (a raw JSON-RPC response with ``result.tools``
also works) or a bare list of tools. The server name is taken from a
``"server"`` key, or from the file name.

Checks (all offline, stdlib only):

* TS001 name-collision    same tool name exposed by two servers
* TS002 confusable-name   names that collapse to the same skeleton after
                          NFKC, case folding, separator stripping and a
                          homoglyph map, or that sit one edit apart
* TS003 cross-reference   a tool description that names another server's
                          tool, worse when the sentence is imperative
                          ("always", "instead of", "before calling" ...)
* TS004 lookalike-purpose two tools on different servers whose descriptions
                          are near duplicates, so the model may pick either
* TS005 hidden-text       zero-width / bidi / Unicode tag characters in a
                          name or description
* TS101 rug-pull          tool definition changed since the lockfile
* TS102 new-tool          tool appeared since the lockfile
* TS103 removed-tool      tool disappeared since the lockfile
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from typing import Dict, Iterable, List, Optional

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

HOMOGLYPHS = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "к": "k",
    "м": "m", "т": "t", "в": "b", "н": "h",
    # Greek
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "τ": "t", "υ": "u", "χ": "x",
    # digit / letter swaps commonly used in typosquats
    "0": "o", "1": "l", "3": "e", "5": "s", "7": "t",
}
HIDDEN_RE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060-\u2064\ufeff\U000e0000-\U000e007f]")
IMPERATIVE_RE = re.compile(
    r"\b(always|never|must|instead(?: of)?|before (?:calling|using|you call|running)|"
    r"after (?:calling|using)|whenever|do not use|don't use|ignore|override|replace|"
    r"prefer this|rather than|redirect|send (?:all|every|a copy)|bcc|cc)\b",
    re.I,
)
WORD_RE = re.compile(r"[a-z0-9]+")
STOP = set(
    "a an the of to and or for in on with by from this that is are be it as at "
    "use used using tool tools returns return given you your can will".split()
)


@dataclass
class Tool:
    server: str
    name: str
    description: str = ""
    schema: dict = field(default_factory=dict)

    @property
    def fqn(self) -> str:
        return f"{self.server}/{self.name}"

    def fingerprint(self) -> str:
        blob = json.dumps(
            {"name": self.name, "description": self.description, "schema": self.schema},
            sort_keys=True, ensure_ascii=False,
        )
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class Finding:
    rule: str
    kind: str
    severity: str
    message: str
    tools: List[str]
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------- loading
def _tools_from_obj(obj, default_server: str) -> List[Tool]:
    server = default_server
    if isinstance(obj, dict):
        server = obj.get("server") or obj.get("name") or default_server
        if "result" in obj and isinstance(obj["result"], dict):
            obj = obj["result"]
        tools = obj.get("tools", [])
    elif isinstance(obj, list):
        tools = obj
    else:
        raise ValueError("unsupported tools dump shape")
    out = []
    for t in tools:
        if not isinstance(t, dict) or "name" not in t:
            continue
        out.append(Tool(
            server=str(server),
            name=str(t["name"]),
            description=str(t.get("description") or ""),
            schema=t.get("inputSchema") or t.get("input_schema") or t.get("parameters") or {},
        ))
    return out


def load_catalog(paths: Iterable[str]) -> List[Tool]:
    tools: List[Tool] = []
    for p in paths:
        with open(p, encoding="utf-8") as fh:
            data = json.load(fh)
        base = os.path.splitext(os.path.basename(p))[0]
        if isinstance(data, dict) and "servers" in data and isinstance(data["servers"], dict):
            for sname, sobj in data["servers"].items():
                tools.extend(_tools_from_obj(sobj, sname))
        else:
            tools.extend(_tools_from_obj(data, base))
    return tools


# ---------------------------------------------------------------- helpers
def skeleton(name: str) -> str:
    s = unicodedata.normalize("NFKC", HIDDEN_RE.sub("", name))
    s = s.replace("I", "l").casefold()  # capital I and lowercase l look identical in most fonts
    s = "".join(HOMOGLYPHS.get(ch, ch) for ch in s)
    s = unicodedata.normalize("NFKD", s)
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    return re.sub(r"[^a-z0-9]", "", s)


def edit_distance(a: str, b: str, cap: int = 2) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _tokens(text: str) -> set:
    return {w for w in WORD_RE.findall(text.lower()) if w not in STOP and len(w) > 2}


def jaccard(a: set, b: set) -> float:
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _sentences(text: str) -> List[str]:
    return [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text) if s.strip()]


def _mentions(text: str, name: str) -> bool:
    if len(name) < 3:
        return False
    pat = r"(?<![A-Za-z0-9_\-])" + re.escape(name) + r"(?![A-Za-z0-9_\-])"
    return re.search(pat, text) is not None


# ---------------------------------------------------------------- checks
def check_catalog(tools: List[Tool], similarity: float = 0.6) -> List[Finding]:
    f: List[Finding] = []
    by_name: Dict[str, List[Tool]] = {}
    for t in tools:
        by_name.setdefault(t.name, []).append(t)

    # TS001 exact collisions across servers
    for name, ts in sorted(by_name.items()):
        servers = sorted({t.server for t in ts})
        if len(servers) > 1:
            f.append(Finding("TS001", "name-collision", "high",
                             f"tool name '{name}' is exposed by {len(servers)} servers "
                             f"({', '.join(servers)}); the client may route calls to either",
                             sorted(t.fqn for t in ts)))

    # TS002 confusables / near names across servers
    seen_pairs = set()
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            if a.server == b.server or a.name == b.name:
                continue
            key = tuple(sorted((a.fqn, b.fqn)))
            if key in seen_pairs:
                continue
            ska, skb = skeleton(a.name), skeleton(b.name)
            if ska and ska == skb:
                seen_pairs.add(key)
                f.append(Finding("TS002", "confusable-name", "high",
                                 f"'{a.name}' and '{b.name}' normalize to the same skeleton "
                                 f"'{ska}' (case, separators, or homoglyphs differ)",
                                 list(key), evidence=f"{a.name!r} vs {b.name!r}"))
            elif min(len(ska), len(skb)) >= 5 and edit_distance(ska, skb, 1) == 1:
                seen_pairs.add(key)
                f.append(Finding("TS002", "confusable-name", "medium",
                                 f"'{a.name}' and '{b.name}' are one edit apart across servers",
                                 list(key), evidence=f"{a.name!r} vs {b.name!r}"))

    # TS003 cross-server references in descriptions
    for t in tools:
        done = set()
        for other in tools:
            if other.server == t.server or other.name in done:
                continue
            if not _mentions(t.description, other.name):
                continue
            done.add(other.name)
            owners = sorted({x.fqn for x in tools if x.name == other.name and x.server != t.server})
            own_copy = any(x.server == t.server and x.name == other.name for x in tools)
            hits = [s for s in _sentences(t.description) if _mentions(s, other.name)]
            imperative = [s for s in hits if IMPERATIVE_RE.search(s)]
            if own_copy and not imperative:
                continue  # plain mention of a name its own server also exposes
            sev = "high" if imperative else "medium"
            ev = (imperative or hits)[0]
            msg = (f"description of {t.fqn} refers to {', '.join(owners)}"
                   + (" with an instruction about how to use it" if imperative else ""))
            if own_copy:
                msg += f" while its own server also exposes '{other.name}' (shadow and steer)"
            f.append(Finding("TS003", "cross-reference", sev, msg,
                             [t.fqn] + owners, evidence=ev[:240]))

    # TS004 lookalike purpose
    toks = {t.fqn: _tokens(t.name.replace("_", " ") + " " + t.description) for t in tools}
    for i, a in enumerate(tools):
        for b in tools[i + 1:]:
            if a.server == b.server or a.name == b.name:
                continue
            s = jaccard(toks[a.fqn], toks[b.fqn])
            if s >= similarity:
                f.append(Finding("TS004", "lookalike-purpose", "low",
                                 f"{a.fqn} and {b.fqn} describe nearly the same job "
                                 f"(similarity {s:.2f}); the model may pick either",
                                 sorted([a.fqn, b.fqn])))

    # TS005 hidden characters
    for t in tools:
        for fld, val in (("name", t.name), ("description", t.description)):
            hidden = HIDDEN_RE.findall(val)
            if hidden:
                cps = ", ".join(sorted({f"U+{ord(c):04X}" for c in hidden}))
                tag_text = "".join(chr(ord(c) - 0xE0000) for c in hidden
                                   if 0xE0020 <= ord(c) <= 0xE007E)
                ev = f"codepoints {cps}" + (f"; tag text decodes to {tag_text!r}" if tag_text else "")
                f.append(Finding("TS005", "hidden-text", "high",
                                 f"{t.fqn} {fld} contains {len(hidden)} invisible character(s)",
                                 [t.fqn], evidence=ev))
    return f


# ---------------------------------------------------------------- lockfile
def make_lock(tools: List[Tool]) -> dict:
    lock: Dict[str, Dict[str, str]] = {}
    for t in sorted(tools, key=lambda x: x.fqn):
        lock.setdefault(t.server, {})[t.name] = t.fingerprint()
    return {"version": 1, "servers": lock}


def check_lock(tools: List[Tool], lock: dict) -> List[Finding]:
    f: List[Finding] = []
    locked = lock.get("servers", {})
    current: Dict[str, Dict[str, Tool]] = {}
    for t in tools:
        current.setdefault(t.server, {})[t.name] = t
    for server, names in sorted(current.items()):
        old = locked.get(server)
        if old is None:
            for n in sorted(names):
                f.append(Finding("TS102", "new-tool", "medium",
                                 f"{server}/{n} comes from a server not in the lockfile",
                                 [f"{server}/{n}"]))
            continue
        for n, t in sorted(names.items()):
            if n not in old:
                f.append(Finding("TS102", "new-tool", "medium",
                                 f"{t.fqn} appeared since the lockfile was written", [t.fqn]))
            elif old[n] != t.fingerprint():
                f.append(Finding("TS101", "rug-pull", "high",
                                 f"{t.fqn} changed its name, description, or schema since it was approved",
                                 [t.fqn], evidence=f"locked {old[n][:12]} now {t.fingerprint()[:12]}"))
        for n in sorted(set(old) - set(names)):
            f.append(Finding("TS103", "removed-tool", "info",
                             f"{server}/{n} is in the lockfile but no longer exposed", [f"{server}/{n}"]))
    return f


def filter_min(findings: List[Finding], min_sev: str) -> List[Finding]:
    floor = SEVERITY_ORDER[min_sev]
    return [x for x in findings if SEVERITY_ORDER[x.severity] >= floor]
