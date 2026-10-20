"""Semantic canonicalisation of a pickle stream (robustness v2).

The v1 canonicaliser cancels one syntactic shape of padding, a nullary push followed by a POP.
An attacker who appends to a throw-away list, leaves junk on the stack, or memoises a value that
is never read again walks past it. This module removes ALL such code at once.

It reads the opcodes with pickletools.genops, which only decodes bytes, and runs an abstract
version of the pickle machine that builds a dataflow graph instead of Python objects. Nothing is
ever imported, called or deserialised. Each value-producing opcode becomes a node whose children
are the values it consumed. Effect nodes are the operations that can run code when the real
loader executes the stream:
  - a call (REDUCE, INST, OBJ, NEWOBJ, NEWOBJ_EX),
  - BUILD (calls __setstate__ or setattr),
  - a mutation of an object that is not a plain literal container (APPEND, SETITEM, ADDITEMS
    on the result of a call run that object's own methods),
  - a persistent load (PERSID, BINPERSID), an extension-registry lookup (EXT1/2/4),
  - an import whose target is outside the allowlist, or whose module or name is not a literal.

The canonical stream is the post-order emission of every node reachable from the effect nodes,
in creation order. A node that no effect consumes cannot influence what the loader executes,
so dropping it changes neither the calls made nor their arguments. Insertion of any such dead
code therefore leaves the canonical stream unchanged, whatever its syntactic shape.

Protocol re-encoding is normalised at the same time:
  - literal opcodes map to one token per type (INT/BININT/LONG1 -> BININT, STRING/UNICODE/
    BINUNICODE -> BINUNICODE, ...), memo, MARK, PROTO and FRAME bookkeeping disappears,
  - tuples, lists and dicts become one container node whatever opcodes built them,
  - STACK_GLOBAL on two literal strings, GLOBAL and INST become the same import token,
  - copyreg._reconstructor(cls, object, None) (protocols 0 and 1) equals NEWOBJ(cls) (2+),
  - _codecs.encode(str, 'latin1') (bytes under protocols 0-2) equals a bytes literal,
  - builtins set / frozenset / list / dict / tuple / bytearray / bytes called on a literal
    argument, and collections.OrderedDict, become pure literal containers (protocols 0-3 write
    a set as set([...]), protocol 4 as EMPTY_SET + ADDITEMS),
  - getattr(<import m.P>, "a") equals the import m.P.a (protocols 0-3 write a nested
    __qualname__ this way, protocol 4 writes STACK_GLOBAL(m, "P.a"); the loader does the same
    lookup either way),
  - batched APPENDS / SETITEMS on an object are split into one effect per item, as protocol 0
    writes them.

The reference semantics is CPython's C unpickler (_pickle.Unpickler, used by pickle.load and
torch.load). Where the loader would raise, the abstract machine raises too, or over-approximates
by carrying on, which can only add effects. The two places where it stops EARLIER than the loader
(the MAX_OPS and MAX_STREAM_BYTES caps) set stats["broken"], and callers must treat a broken
stream as unverified. PROOFS.md in experiments_v2 states and proves the guarantees.

What it does NOT remove: code that calls an allowlisted function and discards the result
(for example torch.zeros), and junk placed inside the arguments of a live call. Those survive as
live nodes. The detector built on this stream must therefore not let added content lower its
score (monotone head), which is the second half of the v2 design.

Everything is linear in the input: one decoding pass, one interpretation pass in which every
opcode and every rewrite costs O(1) amortised (no rewrite copies a container), and iterative
traversals of a graph whose size is O(number of opcodes). Hard caps from features.py bound
memory and time.
"""

from __future__ import annotations

import _compat_pickle
import io
import pickle
import pickletools
from typing import Dict, List, Tuple

from .features import MAX_OPS, MAX_STREAM_BYTES, _is_allowlisted

Op = Tuple[str, object, int]

MAX_STREAMS = 64

_INT = {"INT", "BININT", "BININT1", "BININT2", "LONG", "LONG1", "LONG4"}
_STR = {"STRING", "BINSTRING", "SHORT_BINSTRING", "UNICODE", "BINUNICODE", "SHORT_BINUNICODE",
        "BINUNICODE8"}
_BYTES = {"BINBYTES", "SHORT_BINBYTES", "BINBYTES8", "BYTEARRAY8"}
_FLOAT = {"FLOAT", "BINFLOAT"}
_LITERAL_CONTAINERS = {"LIST", "DICT", "TUPLE", "EMPTY_SET", "FROZENSET"}
_SCALAR_LITERALS = {"BININT", "BINFLOAT", "BINUNICODE", "BINBYTES", "NONE", "NEWTRUE", "NEWFALSE"}
_BUILTINS = ("builtins", "__builtin__")
_PURE_BUILTIN_CTORS = {"set": "EMPTY_SET", "frozenset": "FROZENSET", "list": "LIST", "dict": "DICT",
                       "tuple": "TUPLE", "bytearray": "BINBYTES", "bytes": "BINBYTES"}


class _Broken(Exception):
    """The abstract machine hit an operation the real loader would also reject."""


class _Graph:
    """Parallel arrays, one entry per node, so the interpreter stays cheap."""

    __slots__ = ("tok", "arg", "pos", "kids", "effect", "imp", "used", "flat", "results")

    def __init__(self):
        self.tok: List[str] = []
        self.arg: List[object] = []
        self.pos: List[int] = []
        self.kids: List[List[int]] = []
        self.effect: List[bool] = []
        self.imp: List[object] = []        # (module, name) for a static import, else None
        self.used: List[bool] = []         # consumed by a normalisation rewrite
        self.flat: List[bool] = []         # constructor wrapper whose one child may be inlined
        self.results: List[int] = []       # value returned by each stream's STOP

    def new(self, tok, arg=None, pos=-1, kids=None, effect=False, imp=None, flat=False) -> int:
        self.tok.append(tok)
        self.arg.append(arg)
        self.pos.append(pos)
        self.kids.append(kids if kids is not None else [])
        self.effect.append(effect)
        self.imp.append(imp)
        self.used.append(False)
        self.flat.append(flat)
        return len(self.tok) - 1

    def is_literal_container(self, i: int) -> bool:
        return self.tok[i] in _LITERAL_CONTAINERS and not self.effect[i]

    def literal_str(self, i: int):
        return self.arg[i] if self.tok[i] == "BINUNICODE" and isinstance(self.arg[i], str) else None


def _import(g: _Graph, module: str, name: str, pos: int, proto: int) -> int:
    # The real loader rewrites Python 2 names for protocols 0-2 (Unpickler.find_class with
    # fix_imports). Doing the same keeps our reading identical to what would be imported.
    if proto < 3:
        if (module, name) in _compat_pickle.NAME_MAPPING:
            module, name = _compat_pickle.NAME_MAPPING[(module, name)]
        elif module in _compat_pickle.IMPORT_MAPPING:
            module = _compat_pickle.IMPORT_MAPPING[module]
    return g.new("GLOBAL", arg=f"{module} {name}", pos=pos, imp=(module, name),
                 effect=not _is_allowlisted(module, name))


def _call(g: _Graph, func: int, args: int, pos: int) -> int:
    """REDUCE with the protocol-normalising rewrites. Each rewrite inspects O(1) nodes and copies
    nothing, so calling a constructor many times on one large container stays linear."""
    imp = g.imp[func]
    if imp is not None and g.tok[args] == "TUPLE" and not g.effect[args]:
        mod, name = imp
        a = g.kids[args]
        if mod in ("copyreg", "copy_reg") and name == "_reconstructor" and len(a) == 3:
            base = g.imp[a[1]]
            if base is not None and base[0] in _BUILTINS and base[1] == "object" and g.tok[a[2]] == "NONE":
                for k in (func, args, a[1], a[2]):
                    g.used[k] = True
                return g.new("NEWOBJ", pos=pos, kids=[a[0]], effect=True)
        if mod == "_codecs" and name == "encode" and len(a) == 2:
            enc = g.literal_str(a[1])
            if g.literal_str(a[0]) is not None and enc in ("latin1", "latin-1"):
                for k in (func, args, a[0], a[1]):
                    g.used[k] = True
                return g.new("BINBYTES", arg=None, pos=pos)
        if mod in _BUILTINS and name == "getattr" and len(a) == 2 and g.imp[a[0]] is not None:
            attr = g.literal_str(a[1])
            if attr is not None:
                # The import it replaces is marked used, so it is not reported a second time as
                # a lone import. The module, hence the allowlist verdict, is the same.
                m, parent = g.imp[a[0]]
                for k in (func, args, a[0], a[1]):
                    g.used[k] = True
                qual = f"{parent}.{attr}"
                return g.new("GLOBAL", arg=f"{m} {qual}", pos=pos, imp=(m, qual),
                             effect=not _is_allowlisted(m, qual))
        pure_ctor = None
        if mod in _BUILTINS and name in _PURE_BUILTIN_CTORS:
            pure_ctor = _PURE_BUILTIN_CTORS[name]
        elif mod == "collections" and name == "OrderedDict":
            pure_ctor = "DICT"
        src = a[0] if len(a) == 1 else None
        if pure_ctor is not None and len(a) <= 1 and (
                src is None or g.tok[src] in _SCALAR_LITERALS or g.is_literal_container(src)):
            # On a literal argument these builtins run no user code beyond what the loader runs
            # for EMPTY_SET + ADDITEMS etc. (hashing elements). Effects inside the argument are
            # effect nodes of their own, so nothing is lost.
            for k in (func, args):
                g.used[k] = True
            if pure_ctor == "BINBYTES":
                if src is not None:
                    g.used[src] = True
                return g.new("BINBYTES", pos=pos)
            if src is None:
                return g.new(pure_ctor, pos=pos)
            # Keep the container as the one child instead of copying its children. _emit inlines
            # it when nothing else in the emitted graph refers to it, which is always the case for
            # what pickle.Pickler writes, so the result equals the protocol-4 form.
            flat = g.is_literal_container(src) and (g.tok[src] == "DICT") == (pure_ctor == "DICT")
            return g.new(pure_ctor, pos=pos, kids=[src], flat=flat)
    return g.new("REDUCE", pos=pos, kids=[func, args], effect=True)


def _mutate(g: _Graph, target: int, items: List[int], kind: str, pos: int, step: int) -> None:
    """APPEND(S) / SETITEM(S) / ADDITEMS. Pure on a literal container, otherwise one effect
    node per item (per key-value pair), matching protocol 0's unbatched form."""
    if step == 2 and len(items) % 2:
        raise _Broken("odd SETITEMS")           # the C loader checks this before any update
    container_kind = {"APPEND": "LIST", "SETITEM": "DICT", "ADDITEMS": "EMPTY_SET"}[kind]
    if g.tok[target] == container_kind and g.is_literal_container(target):
        g.kids[target].extend(items)
        return
    for j in range(0, len(items), step):
        g.new(kind, pos=pos, kids=[target] + items[j:j + step], effect=True)


def _interpret_stream(g: _Graph, ops) -> None:
    """Abstract execution of one pickle stream. Mirrors pickle._Unpickler's dispatch table."""
    stack: List[int] = []
    metastack: List[List[int]] = []
    memo: Dict[int, int] = {}
    proto = 0

    def pop():
        if not stack:
            raise _Broken("stack underflow")
        return stack.pop()

    def pop_mark():
        nonlocal stack
        if not metastack:
            raise _Broken("no mark")
        items = stack
        stack = metastack.pop()
        return items

    def top():
        if not stack:
            raise _Broken("empty stack")
        return stack[-1]

    for name, arg, pos in ops:
        if name == "MARK":
            metastack.append(stack)
            stack = []
        elif name == "STOP":
            g.results.append(pop())
            return
        elif name == "POP":
            if stack:
                stack.pop()
            else:
                pop_mark()
        elif name == "POP_MARK":
            pop_mark()
        elif name == "DUP":
            stack.append(top())
        elif name in _INT:
            tok = "BININT"
            if arg is True:
                tok = "NEWTRUE"
            elif arg is False:
                tok = "NEWFALSE"
            stack.append(g.new(tok, arg=arg, pos=pos))
        elif name in _STR:
            stack.append(g.new("BINUNICODE", arg=arg if isinstance(arg, str) else None, pos=pos))
        elif name in _BYTES:
            stack.append(g.new("BINBYTES", pos=pos))
        elif name in _FLOAT:
            stack.append(g.new("BINFLOAT", arg=arg, pos=pos))
        elif name == "NONE":
            stack.append(g.new("NONE", pos=pos))
        elif name in ("NEWTRUE", "NEWFALSE"):
            stack.append(g.new(name, pos=pos))
        elif name == "NEXT_BUFFER":
            stack.append(g.new("NEXT_BUFFER", pos=pos))
        elif name == "READONLY_BUFFER":
            top()                                   # wraps the top value, no new node
        elif name in ("EMPTY_LIST", "EMPTY_DICT", "EMPTY_TUPLE", "EMPTY_SET"):
            tok = {"EMPTY_LIST": "LIST", "EMPTY_DICT": "DICT", "EMPTY_TUPLE": "TUPLE",
                   "EMPTY_SET": "EMPTY_SET"}[name]
            stack.append(g.new(tok, pos=pos))
        elif name in ("LIST", "TUPLE", "FROZENSET"):
            items = pop_mark()                      # before stack.append binds the old list
            stack.append(g.new(name, pos=pos, kids=items))
        elif name == "DICT":
            items = pop_mark()
            if len(items) % 2:
                raise _Broken("odd DICT")
            stack.append(g.new("DICT", pos=pos, kids=items))
        elif name in ("TUPLE1", "TUPLE2", "TUPLE3"):
            n = int(name[-1])
            if len(stack) < n:
                raise _Broken("stack underflow")
            items = stack[-n:]
            del stack[-n:]
            stack.append(g.new("TUPLE", pos=pos, kids=items))
        elif name == "APPEND":
            v = pop()
            _mutate(g, top(), [v], "APPEND", pos, 1)
        elif name == "APPENDS":
            items = pop_mark()
            _mutate(g, top(), items, "APPEND", pos, 1)
        elif name == "SETITEM":
            v = pop()
            k = pop()
            _mutate(g, top(), [k, v], "SETITEM", pos, 2)
        elif name == "SETITEMS":
            items = pop_mark()
            _mutate(g, top(), items, "SETITEM", pos, 2)
        elif name == "ADDITEMS":
            items = pop_mark()
            _mutate(g, top(), items, "ADDITEMS", pos, 1)
        elif name in ("GET", "BINGET", "LONG_BINGET"):
            if arg not in memo:
                raise _Broken("memo miss")
            stack.append(memo[arg])
        elif name in ("PUT", "BINPUT", "LONG_BINPUT"):
            memo[arg] = top()
        elif name == "MEMOIZE":
            memo[len(memo)] = top()
        elif name == "PROTO":
            if not isinstance(arg, int) or not 0 <= arg <= pickle.HIGHEST_PROTOCOL:
                raise _Broken("unsupported protocol")   # the loader raises ValueError here
            proto = arg
        elif name == "FRAME":
            pass
        elif name == "GLOBAL":
            parts = str(arg).split(" ", 1)
            stack.append(_import(g, parts[0], parts[1] if len(parts) > 1 else "", pos, proto))
        elif name == "STACK_GLOBAL":
            nm = pop()
            mod = pop()
            ms, ns = g.literal_str(mod), g.literal_str(nm)
            if ms is not None and ns is not None:
                g.used[mod] = g.used[nm] = True
                stack.append(_import(g, ms, ns, pos, proto))
            else:                                   # module or name computed at load time
                stack.append(g.new("STACK_GLOBAL", pos=pos, kids=[mod, nm], effect=True))
        elif name == "INST":
            parts = str(arg).split(" ", 1)
            items = pop_mark()
            cls = _import(g, parts[0], parts[1] if len(parts) > 1 else "", pos, proto)
            stack.append(_call(g, cls, g.new("TUPLE", pos=pos, kids=items), pos))
        elif name == "OBJ":
            items = pop_mark()
            if not items:
                raise _Broken("empty OBJ")
            stack.append(_call(g, items[0], g.new("TUPLE", pos=pos, kids=items[1:]), pos))
        elif name == "REDUCE":
            args = pop()
            func = pop()
            stack.append(_call(g, func, args, pos))
        elif name == "NEWOBJ":
            args = pop()
            cls = pop()
            kids = [cls] if (g.tok[args] == "TUPLE" and not g.kids[args]) else [cls, args]
            if len(kids) == 1:
                g.used[args] = True
            stack.append(g.new("NEWOBJ", pos=pos, kids=kids, effect=True))
        elif name == "NEWOBJ_EX":
            kwargs = pop()
            args = pop()
            cls = pop()
            kids = [cls]
            empty_kw = g.tok[kwargs] == "DICT" and not g.kids[kwargs]
            empty_args = g.tok[args] == "TUPLE" and not g.kids[args]
            if not (empty_args and empty_kw):
                kids.append(args)
            else:
                g.used[args] = True
            if not empty_kw:
                kids.append(kwargs)
            else:
                g.used[kwargs] = True
            stack.append(g.new("NEWOBJ", pos=pos, kids=kids, effect=True))
        elif name == "BUILD":
            state = pop()
            g.new("BUILD", pos=pos, kids=[top(), state], effect=True)
        elif name == "PERSID":
            pid = g.new("BINUNICODE", arg=arg if isinstance(arg, str) else None, pos=pos)
            stack.append(g.new("BINPERSID", pos=pos, kids=[pid], effect=True))
        elif name == "BINPERSID":
            stack.append(g.new("BINPERSID", pos=pos, kids=[pop()], effect=True))
        elif name in ("EXT1", "EXT2", "EXT4"):
            stack.append(g.new("EXT1", arg=arg, pos=pos, effect=True))
        else:
            raise _Broken("unknown opcode " + str(name))
    raise _Broken("no STOP")


def _decode_streams(inner: bytes, stats: Dict) -> List[List[Op]]:
    """Decode up to MAX_STREAMS back-to-back pickle streams. Bytes after the last complete
    stream that do not start a parseable stream are trailing junk, which the loader never runs."""
    streams: List[List[Op]] = []
    bio = io.BytesIO(inner)
    total = 0
    while bio.tell() < len(inner) and len(streams) < MAX_STREAMS:
        start = bio.tell()
        ops: List[Op] = []
        err = False
        try:
            for op, arg, pos in pickletools.genops(bio):
                ops.append((op.name, arg, pos))
                total += 1
                if total >= MAX_OPS:
                    err = True
                    break
        except Exception:
            err = True
        if not ops:
            stats["trailing_bytes"] = len(inner) - start
            break
        streams.append(ops)
        if err:
            if len(streams) == 1:
                stats["broken"] = True
            else:
                stats["broken_later_stream"] = True
            break
        bio.seek(ops[-1][2] + 1)
    return streams


def semantic_canonicalize(inner: bytes, view: str = "effects") -> Tuple[List[Op], Dict]:
    """Return (canonical op stream, stats) for an already-unwrapped pickle stream.

    view="effects": only what effect nodes consume (default, the most robust view).
    view="full":    also the values each stream returns, so pure data stays visible.
    The returned ops use real opcode names, so existing vocabularies keep working.
    """
    stats: Dict = {"broken": False, "broken_later_stream": False, "trailing_bytes": 0,
                   "n_streams": 0, "n_ops_raw": 0}
    if not inner or len(inner) > MAX_STREAM_BYTES:
        stats["broken"] = True
        return [], _finish_stats(_Graph(), stats, [], set())
    streams = _decode_streams(inner, stats)
    if not streams:
        stats["broken"] = True                  # not even one opcode decodes
    stats["n_streams"] = len(streams)
    stats["n_ops_raw"] = sum(len(s) for s in streams)
    g = _Graph()
    for s in streams:
        try:
            _interpret_stream(g, s)
        except _Broken:
            # The real loader stops at the same point. Effects created so far did run, so
            # they are kept. Values still on the abstract stack are never consumed.
            if s is streams[0]:
                stats["broken"] = True
            else:
                stats["broken_later_stream"] = True
            break
        except Exception:
            stats["broken"] = True
            break

    # Imports are leaf atoms: they are inlined wherever used, never emitted as a back-reference.
    effects = [i for i in range(len(g.tok)) if g.effect[i] and g.imp[i] is None]
    roots = list(effects)
    if view == "full":
        roots += g.results
    reached = _reach(g, roots)
    # A non-allowlisted import that nothing uses is still an effect (importing runs module code),
    # unless a rewrite folded it into another import of the same module.
    lone = [i for i in range(len(g.tok))
            if g.effect[i] and g.imp[i] is not None and not g.used[i] and i not in reached]
    # Roots in creation order, built in one linear pass (no sort).
    keep = set(effects) | set(lone)
    order = [i for i in range(len(g.tok)) if i in keep]
    if view == "full":
        order += [r for r in g.results if r not in keep]
    out = _emit(g, order)
    live_full = _reach(g, effects + lone + g.results)
    return out, _finish_stats(g, stats, out, live_full)


def _reach(g: _Graph, roots: List[int]) -> set:
    seen = set()
    todo = list(roots)
    while todo:
        i = todo.pop()
        if i in seen:
            continue
        seen.add(i)
        todo.extend(g.kids[i])
    return seen


def _emit(g: _Graph, order: List[int]) -> List[Op]:
    """Iterative post-order emission. A non-import node met a second time becomes BINGET, so
    shared and self-referencing structures stay finite. A constructor wrapper (set([...]) and
    friends) whose container has no other referrer in the emitted graph is emitted with the
    container's children, the protocol-4 form. Linear: one reach, one in-degree count, one walk."""
    roots = set(order)
    indeg: Dict[int, int] = {}
    for i in _reach(g, order):
        for k in g.kids[i]:
            indeg[k] = indeg.get(k, 0) + 1

    def kids_of(node):
        ks = g.kids[node]
        if g.flat[node] and indeg.get(ks[0], 0) == 1 and ks[0] not in roots:
            return g.kids[ks[0]]
        return ks

    state = bytearray(len(g.tok))       # 0 new, 1 in progress, 2 emitted
    out: List[Op] = []
    for r in order:
        if state[r] and g.imp[r] is None:
            continue
        work = [[r, 0, kids_of(r)]]
        if g.imp[r] is None:
            state[r] = 1
        while work:
            top = work[-1]
            node, ci, kids = top
            if ci < len(kids):
                top[1] += 1
                c = kids[ci]
                if g.imp[c] is not None:
                    out.append(("GLOBAL", g.arg[c], g.pos[c]))
                elif state[c] == 0:
                    state[c] = 1
                    work.append([c, 0, kids_of(c)])
                else:
                    out.append(("BINGET", None, g.pos[c]))
            else:
                out.append((g.tok[node], g.arg[node], g.pos[node]))
                if g.imp[node] is None:
                    state[node] = 2
                work.pop()
    if order:
        out.append(("STOP", None, -1))
    return out


def _finish_stats(g: _Graph, stats: Dict, out: List[Op], live_full: set) -> Dict:
    n = len(g.tok)
    dead = sum(1 for i in range(n) if i not in live_full and not g.used[i])
    imports = [g.imp[i] for i in range(n) if g.imp[i] is not None and i in live_full]
    nonallow = [(m, nm) for (m, nm) in imports if not _is_allowlisted(m, nm)]
    stats.update({
        "n_nodes": n,
        "n_effects": sum(1 for i in range(n) if g.effect[i]),
        "n_calls": sum(1 for i in range(n) if g.tok[i] in ("REDUCE", "NEWOBJ") and g.effect[i]),
        "n_dynamic_imports": sum(1 for i in range(n) if g.tok[i] in ("STACK_GLOBAL", "EXT1")),
        "n_static_imports": len(imports),
        "n_nonallow_imports": sum(1 for m, nm in imports if not _is_allowlisted(m, nm)),
        "n_persid": sum(1 for i in range(n) if g.tok[i] == "BINPERSID"),
        "n_dead_nodes": dead,
        "dead_fraction": (dead / n) if n else 0.0,
        "n_emitted": len(out),
        "imports": sorted({f"{m}.{nm}" for m, nm in imports}),
        # Non-allowlisted imports kept as "module name" so a consumer can bucket
        # the module without re-parsing. These are the live, reachable imports the
        # loader would run that fall outside the ML allowlist, so they are the
        # evidence the v2 monotone import gate scores.
        "nonallow_imports": sorted({f"{m} {nm}" for (m, nm) in nonallow}),
    })
    return stats
