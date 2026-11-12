"""Finding functions in lexed JavaScript / TypeScript (see jslex): declarations, arrow
functions, object methods and class methods, with their parameter list and body spans."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .jslex import match_close

IDENT = r"[A-Za-z_$][\w$]*"
KEYWORDS = {"if", "for", "while", "switch", "catch", "function", "return", "await", "new", "typeof", "const", "let",
            "var", "async", "true", "false", "null", "undefined", "this", "of", "in", "instanceof", "else", "case",
            "default", "throw", "try", "delete", "void", "yield", "import", "export", "from", "as", "class",
            "super", "do", "with", "get", "set", "static", "constructor"}

@dataclass
class Fn:
    name: str | None
    start: int        # declaration start (for line numbers)
    popen: int        # '(' of the parameter list (or start of the single param)
    bopen: int        # body start ('{' or first char of an expression body)
    bend: int         # index after the body


def stmt_end(code: str, i: int) -> int:
    """Index after the expression/statement starting at i (depth-aware)."""
    depth, n = 0, len(code)
    j = i
    while j < n:
        c = code[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            if depth == 0:
                return j
            depth -= 1
        elif depth == 0 and c in ";,":
            return j
        elif depth == 0 and c == "\n":
            k = j + 1
            while k < n and code[k] in " \t\r\n":
                k += 1
            if k >= n or code[k] not in ".?:+-*/&|=)]}":
                prev = code[i:j].rstrip()
                if not prev.endswith(("=", "(", ",", "+", "-", "*", "/", "&&", "||", "?", ":", "=>", ".")):
                    return j
        j += 1
    return n


def _body_after_params(code: str, pclose: int, arrow: bool | None) -> tuple[int, int] | None:
    """After the ')' of a parameter list: (body_start, body_end) of a block or arrow body.
    arrow=True requires '=>', False forbids it, None allows both."""
    m = re.compile(r"\s*(?::[^{;=()]*?(?:<[^;{}]*>)?)?\s*(=>)?\s*").match(code, pclose + 1)
    if not m:
        return None
    k = m.end()
    has_arrow = bool(m.group(1))
    if (arrow is True and not has_arrow) or (arrow is False and has_arrow):
        return None
    if k < len(code) and code[k] == "{":
        return k, match_close(code, k) + 1
    if has_arrow:
        return k, stmt_end(code, k)
    return None


FUNC_KW_RE = re.compile(r"(?<![\w$.])function\b\s*\*?\s*(" + IDENT + r")?\s*(?:<[^>()]*>)?\s*\(")
ARROW_DECL_RE = re.compile(r"(?<![\w$.])(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*(?:async\s*)?"
                           r"(\(|" + IDENT + r"\s*=>)")
PROP_ARROW_RE = re.compile(r"(?<![\w$.])(" + IDENT + r")\s*:\s*(?:async\s*)?(\(|" + IDENT + r"\s*=>)")
METHOD_RE = re.compile(r"(?m)^[ \t]*(?:(?:public|private|protected|static|async|override|export|default)\s+)*"
                       r"(" + IDENT + r")\s*(?:<[^>()]*>)?\s*\(")
ASSIGN_NAME_RE = re.compile(r"(?:const|let|var)\s+(" + IDENT + r")\s*(?::[^=;]+)?=\s*(?:async\s+)?$")


def find_functions(code: str) -> list[Fn]:
    fns: dict[int, Fn] = {}

    def add(name, start, popen, body):
        if body and popen not in fns:
            fns[popen] = Fn(name, start, popen, body[0], body[1])

    for m in FUNC_KW_RE.finditer(code):
        popen = m.end() - 1
        name = m.group(1)
        if not name:
            b = ASSIGN_NAME_RE.search(code[max(0, m.start() - 160):m.start()])
            name = b.group(1) if b else None
        add(name, m.start(), popen, _body_after_params(code, match_close(code, popen), False))
    for rx in (ARROW_DECL_RE, PROP_ARROW_RE):
        for m in rx.finditer(code):
            if m.group(1) in KEYWORDS:
                continue
            if m.group(2) == "(":
                popen = m.end() - 1
                add(m.group(1), m.start(), popen, _body_after_params(code, match_close(code, popen), True))
            else:
                popen = m.start(2)
                arrow = code.index("=>", popen)
                k = arrow + 2
                while k < len(code) and code[k] in " \t\r\n":
                    k += 1
                body = (k, match_close(code, k) + 1) if k < len(code) and code[k] == "{" else (k, stmt_end(code, k))
                add(m.group(1), m.start(), popen, body)
    for m in METHOD_RE.finditer(code):
        name = m.group(1)
        if name in KEYWORDS or name == "function":
            continue
        popen = m.end() - 1
        add(name, m.start(1), popen, _body_after_params(code, match_close(code, popen), False))
    return sorted(fns.values(), key=lambda f: f.popen)

