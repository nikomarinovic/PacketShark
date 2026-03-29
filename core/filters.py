"""
core/filters.py
---------------
Filter engine for the packet list.

Supports human-friendly filter expressions inspired by Wireshark's
display filter syntax, plus a BPF-style subset.

Supported filter examples
--------------------------
  tcp
  udp
  icmp
  dns
  http
  arp
  ip.src == 192.168.1.1
  ip.dst == 8.8.8.8
  port 80
  port == 443
  src 10.0.0.1
  dst 10.0.0.2
  len > 500
  proto tcp && ip.src == 10.0.0.1   (AND)
  tcp || udp                         (OR)
"""

from __future__ import annotations
import re
from typing import Optional

from core.packet_model import PacketRecord


# ------------------------------------------------------------------ #
# Public API
# ------------------------------------------------------------------ #

def compile_filter(expr: str) -> Optional["CompiledFilter"]:
    """
    Parse *expr* and return a CompiledFilter, or None if expr is empty.
    Raises ValueError with a human-readable message on syntax error.
    """
    expr = expr.strip()
    if not expr:
        return None
    return CompiledFilter(expr)


class CompiledFilter:
    """Wraps a parsed filter expression and can test PacketRecords."""

    def __init__(self, expr: str) -> None:
        self._expr = expr
        self._fn = _parse_expr(expr)

    def matches(self, rec: PacketRecord) -> bool:
        try:
            return bool(self._fn(rec))
        except Exception:
            return False

    def __repr__(self) -> str:
        return f"CompiledFilter({self._expr!r})"


# ------------------------------------------------------------------ #
# Parser — recursive descent, handles && / || / ! / ()
# ------------------------------------------------------------------ #

def _parse_expr(expr: str):
    tokens = _tokenize(expr)
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume():
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_or():
        left = parse_and()
        while peek() in ("||", "or"):
            consume()
            right = parse_and()
            l, r = left, right
            left = lambda rec, a=l, b=r: a(rec) or b(rec)
        return left

    def parse_and():
        left = parse_not()
        while peek() in ("&&", "and"):
            consume()
            right = parse_not()
            l, r = left, right
            left = lambda rec, a=l, b=r: a(rec) and b(rec)
        return left

    def parse_not():
        if peek() in ("!", "not"):
            consume()
            inner = parse_atom()
            return lambda rec, f=inner: not f(rec)
        return parse_atom()

    def parse_atom():
        t = peek()
        if t is None:
            raise ValueError("Unexpected end of filter expression")
        if t == "(":
            consume()
            fn = parse_or()
            if peek() != ")":
                raise ValueError("Missing closing parenthesis")
            consume()
            return fn
        # Everything else is a simple predicate
        return _parse_predicate(tokens, pos)

    fn = parse_or()
    if pos[0] < len(tokens):
        raise ValueError(f"Unexpected token: {tokens[pos[0]]!r}")
    return fn


def _tokenize(expr: str) -> list[str]:
    """Split expression into tokens, preserving quoted strings."""
    token_re = re.compile(
        r'(\|\||&&|[()!]|'           # operators / parens
        r'"[^"]*"|\'[^\']*\'|'        # quoted strings
        r'[^\s()!&|]+)'               # bare words / numbers
    )
    return [m.group(0) for m in token_re.finditer(expr)]


def _parse_predicate(tokens: list[str], pos: list[int]):
    """
    Parse a single predicate from the token list starting at pos[0].
    Returns a callable (PacketRecord -> bool).
    Advances pos[0] past the consumed tokens.
    """
    def consume():
        t = tokens[pos[0]]
        pos[0] += 1
        return t.lower()

    def peek():
        return tokens[pos[0]].lower() if pos[0] < len(tokens) else None

    keyword = consume()

    # ── bare protocol keywords ─────────────────────────────────── #
    if keyword in ("tcp", "udp", "icmp", "icmpv6", "dns",
                   "http", "https", "arp", "ipv4", "ipv6",
                   "ethernet"):
        proto = keyword.upper()
        return lambda rec, p=proto: rec.protocol == p

    # ── ip.src / ip.dst ───────────────────────────────────────── #
    if keyword in ("ip.src", "ip.dst", "src", "dst"):
        op = _maybe_op(tokens, pos)
        value = consume()
        field = "src" if "src" in keyword else "dst"
        return _make_str_compare(field, op, value)

    # ── port ──────────────────────────────────────────────────── #
    if keyword == "port":
        op = _maybe_op(tokens, pos)
        value = consume()
        return _make_port_filter(op, value)

    # ── len / length ──────────────────────────────────────────── #
    if keyword in ("len", "length"):
        op = _maybe_op(tokens, pos) or "=="
        value = int(consume())
        return _make_int_compare("length", op, value)

    # ── proto ─────────────────────────────────────────────────── #
    if keyword == "proto":
        op = _maybe_op(tokens, pos)
        value = consume().upper()
        return lambda rec, v=value: rec.protocol == v

    raise ValueError(f"Unknown filter keyword: {keyword!r}")


def _maybe_op(tokens: list[str], pos: list[int]) -> Optional[str]:
    """Peek ahead; if next token is a comparison op, consume and return it."""
    ops = {"==", "!=", ">", "<", ">=", "<=", "="}
    if pos[0] < len(tokens) and tokens[pos[0]] in ops:
        op = tokens[pos[0]]
        pos[0] += 1
        return op
    return None


def _make_str_compare(field: str, op: Optional[str], value: str):
    op = op or "=="
    def fn(rec: PacketRecord, f=field, o=op, v=value) -> bool:
        actual = getattr(rec, f, "")
        # Strip port suffix for IP comparison
        if ":" in actual:
            actual = actual.rsplit(":", 1)[0]
        if o in ("==", "="):  return actual == v
        if o == "!=":         return actual != v
        return False
    return fn


def _make_int_compare(field: str, op: str, value: int):
    def fn(rec: PacketRecord, f=field, o=op, v=value) -> bool:
        actual = getattr(rec, f, 0)
        if o in ("==", "="): return actual == v
        if o == "!=":        return actual != v
        if o == ">":         return actual > v
        if o == "<":         return actual < v
        if o == ">=":        return actual >= v
        if o == "<=":        return actual <= v
        return False
    return fn


def _make_port_filter(op: Optional[str], value: str):
    """Match port number in src or dst (stripped from 'addr:port' format)."""
    try:
        port = int(value)
    except ValueError:
        raise ValueError(f"Invalid port: {value!r}")
    op = op or "=="
    def fn(rec: PacketRecord, p=port, o=op) -> bool:
        for addr in (rec.src, rec.dst):
            if ":" in addr:
                try:
                    pnum = int(addr.rsplit(":", 1)[1])
                    if o in ("==", "=") and pnum == p: return True
                    if o == "!=" and pnum != p:         return True
                    if o == ">"  and pnum > p:          return True
                    if o == "<"  and pnum < p:          return True
                    if o == ">=" and pnum >= p:         return True
                    if o == "<=" and pnum <= p:         return True
                except (ValueError, IndexError):
                    pass
        return False
    return fn
