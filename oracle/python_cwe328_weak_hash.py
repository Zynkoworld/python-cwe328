"""python-cwe328 -- weak hash primitive (Bandit B303-ekvivalens szabaly, SAJAT ast-implementacio).

decide(code, line) -> "FLAG" | "SAFE".  FLAG iff a megadott soron GYENGE hash-primitivet hivnak
(hashlib.md5/sha1/md4/sha, vagy Crypto/Cryptodome MD5/SHA1 new()), ES nincs `usedforsecurity=False`
kizaras (a CPython 3.9+ explicit nem-biztonsagi jelolese). stdlib `ast` only, nincs futtatas.
NO-VIRUS: a Bandit szabalya ujraimplementalva, a Bandit NINCS telepitve/futtatva.
"""
import ast

CWE = "CWE-328"
_WEAK = {"md5", "sha1", "md4", "sha", "new"}
_WEAK_NEW_ARG = {"md5", "sha1", "md4", "sha"}


def _is_weak_call(node):
    """hashlib.md5(...) / md5(...) / hashlib.new('md5') / Crypto.Hash.MD5.new()"""
    f = node.func
    name = f.attr if isinstance(f, ast.Attribute) else (f.id if isinstance(f, ast.Name) else None)
    if name is None:
        return False
    low = name.lower()
    if low in ("md5", "sha1", "md4", "sha"):
        return True
    if low == "new":
        # hashlib.new("md5") vagy MD5.new()
        for a in node.args:
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.lower() in _WEAK_NEW_ARG:
                return True
        mod = f.value if isinstance(f, ast.Attribute) else None
        mod_name = mod.attr if isinstance(mod, ast.Attribute) else (mod.id if isinstance(mod, ast.Name) else "")
        if str(mod_name).lower() in _WEAK_NEW_ARG:
            return True
    return False


def _has_nonsecurity_marker(node):
    for kw in (node.keywords or []):
        if kw.arg == "usedforsecurity" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def decide(code, line):
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return "SAFE"
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node, "lineno", None) == line:
            if _is_weak_call(node) and not _has_nonsecurity_marker(node):
                return "FLAG"
    return "SAFE"
