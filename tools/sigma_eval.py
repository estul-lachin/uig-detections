"""A small Sigma evaluator: runs rules against JSON test events.

It implements the subset of Sigma these rules use and fails loudly on
anything else, so an unsupported construct can never pass silently:

- detection items: maps (AND), lists of maps (OR), value lists (OR)
- modifiers: contains, startswith, endswith, re, all; plain values with * and ? wildcards
- string matching is case-insensitive except |re (case-sensitive unless (?i))
- conditions: and, or, not, parentheses, "1 of x*", "all of x*", "1 of them", "all of them"
- correlations: event_count, value_count, temporal, over fixed time buckets
  aligned to the epoch, which is what Splunk's `bin` and KQL's bin() do
"""

import datetime
import fnmatch
import re

MODIFIERS = {"contains", "startswith", "endswith", "re", "all"}
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


class Unsupported(Exception):
    pass


# ---------------------------------------------------------------- single events

def _match_value(actual, expected, mods):
    if expected is None:
        return actual is None
    if actual is None:
        return False
    a, e = str(actual), str(expected)
    if "re" in mods:
        return re.search(e, a) is not None
    a, e = a.lower(), e.lower()
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    if "*" in e or "?" in e:
        return fnmatch.fnmatchcase(a, e)
    return a == e


def _match_field(event, key, expected):
    field, *mods = key.split("|")
    unknown = set(mods) - MODIFIERS
    if unknown:
        raise Unsupported(f"modifier(s) {sorted(unknown)} in {key!r}")
    values = expected if isinstance(expected, list) else [expected]
    hits = (_match_value(event.get(field), v, mods) for v in values)
    return all(hits) if "all" in mods else any(hits)


def _match_selection(event, sel):
    if isinstance(sel, dict):
        return all(_match_field(event, k, v) for k, v in sel.items())
    if isinstance(sel, list) and all(isinstance(x, dict) for x in sel):
        return any(_match_selection(event, x) for x in sel)
    raise Unsupported("keyword (value-only) selections are not supported")


def _tokens(cond):
    return re.findall(r"\(|\)|[^\s()]+", cond)


def _condition(cond, names):
    """Compile a condition string into a function of {selection: bool}."""
    toks = _tokens(cond)
    pos = 0

    def peek():
        return toks[pos].lower() if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def group(pattern):
        found = [n for n in names if fnmatch.fnmatchcase(n, pattern)] if pattern != "them" else list(names)
        if not found:
            raise Unsupported(f"no selection matches {pattern!r}")
        return found

    def atom():
        t = peek()
        if t is None:
            raise Unsupported(f"condition ends early: {cond!r}")
        if t == "(":
            take()
            f = expr()
            if take() != ")":
                raise Unsupported(f"unbalanced parentheses: {cond!r}")
            return f
        if t == "not":
            take()
            f = atom()
            return lambda r: not f(r)
        if t in ("1", "all") and pos + 1 < len(toks) and toks[pos + 1].lower() == "of":
            quant = take().lower()
            take()
            members = group(take())
            if quant == "1":
                return lambda r: any(r[m] for m in members)
            return lambda r: all(r[m] for m in members)
        name = take()
        if name not in names:
            raise Unsupported(f"unknown selection {name!r} in condition")
        return lambda r: r[name]

    def conj():
        f = atom()
        while peek() == "and":
            take()
            g, h = f, atom()
            f = lambda r, g=g, h=h: g(r) and h(r)
        return f

    def expr():
        f = conj()
        while peek() == "or":
            take()
            g, h = f, conj()
            f = lambda r, g=g, h=h: g(r) or h(r)
        return f

    fn = expr()
    if pos != len(toks):
        raise Unsupported(f"unexpected {toks[pos]!r} in condition {cond!r}")
    return fn


def compile_rule(detection):
    """Return match(event) -> bool for a Sigma 'detection' block."""
    detection = dict(detection)
    cond = detection.pop("condition")
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Unsupported("multiple conditions")
        cond = cond[0]
    if "timeframe" in detection:
        raise Unsupported("timeframe: use a correlation rule")
    fn = _condition(cond, list(detection))

    def match(event):
        return fn({name: _match_selection(event, sel) for name, sel in detection.items()})
    return match


# ---------------------------------------------------------------- correlations

def seconds(timespan):
    m = re.fullmatch(r"(\d+)([smhd])", str(timespan))
    if not m:
        raise Unsupported(f"timespan {timespan!r}")
    return int(m.group(1)) * UNITS[m.group(2)]


def epoch(event):
    ts = event["timestamp"]
    return datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()


def _compare(value, condition):
    ops = {"gt": value.__gt__, "gte": value.__ge__, "lt": value.__lt__,
           "lte": value.__le__, "eq": value.__eq__}
    checks = [(k, v) for k, v in condition.items() if k != "field"]
    if not checks or any(k not in ops for k, _ in checks):
        raise Unsupported(f"correlation condition {condition!r}")
    return all(ops[k](v) for k, v in checks)


def correlate(corr, base_matchers, events, events_out=None):
    """Groups that fire: list of (bucket start, group key, value).

    With events_out (a list), the events of every group that fires are appended to it.
    """
    kind, span = corr["type"], seconds(corr["timespan"])
    group_by = corr.get("group-by", [])
    buckets = {}
    for ev in events:
        hits = [name for name, m in base_matchers.items() if m(ev)]
        if not hits:
            continue
        b = int(epoch(ev) // span * span)
        key = (b, tuple(str(ev.get(g)) for g in group_by))
        buckets.setdefault(key, []).append((ev, hits))
    fired = []
    for (b, key), items in sorted(buckets.items()):
        if kind == "event_count":
            value, ok = len(items), _compare(len(items), corr["condition"])
        elif kind == "value_count":
            field = corr["condition"]["field"]
            value = len({str(ev.get(field)) for ev, _ in items})
            ok = _compare(value, corr["condition"])
        elif kind == "temporal":
            value = len({h for _, hits in items for h in hits})
            ok = value >= len(base_matchers)
        else:
            raise Unsupported(f"correlation type {kind!r}")
        if ok:
            fired.append((b, key, value))
            if events_out is not None:
                events_out.extend(ev for ev, _ in items)
    return fired
