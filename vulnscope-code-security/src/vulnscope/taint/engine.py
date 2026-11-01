"""Flow-insensitive-per-branch, statement-ordered taint analysis with inter-procedural summaries.

For every function:
  * a taint environment maps variable names -> trace (list[TraceStep]) of how the value became tainted
  * parameters start with a symbolic 'param' taint so we can compute summaries:
      - sink_params:  param index -> sinks reachable from that param
      - ret_params:   params whose taint reaches the return value
      - ret_source:   return value is tainted by a real source
  * Flask/Django route handlers: parameters are treated as real sources (URL path input)
Summaries are iterated to a fixed point (bounded), then findings are collected."""
from __future__ import annotations
import ast
from dataclasses import dataclass, field

from vulnscope.models import Finding, TraceStep
from vulnscope.parser.ast_index import ImportMap, dotted, index_functions
from vulnscope.taint import spec

Trace = list[TraceStep]


@dataclass
class Summary:
    sink_params: dict[int, list[tuple]] = field(default_factory=dict)   # idx -> [(cwe,title,line,trace)]
    ret_params: set[int] = field(default_factory=set)
    ret_source: Trace | None = None


def _is_route(decorators: list[str]) -> bool:
    return any(d.endswith((".route", ".get", ".post", ".put", ".delete", ".api_view")) for d in decorators)


class _FunctionAnalyzer:
    def __init__(self, ctx, qualname, node, params, is_route):
        self.ctx, self.qualname, self.node = ctx, qualname, node
        self.env: dict[str, Trace] = {}
        self.params = params
        for i, p in enumerate(params):
            if p in ("self", "cls"):
                continue
            kind = "source" if is_route else "param"
            self.env[p] = [TraceStep(node.lineno, kind, f"{'route parameter' if is_route else 'parameter'} '{p}'")]
        self.summary = Summary()
        self.sanitized: set[str] = set()

    # ---------- expression taint ----------
    def taint(self, e) -> Trace | None:
        if e is None or isinstance(e, ast.Constant):
            return None
        if isinstance(e, ast.Name):
            return self.env.get(e.id)
        if isinstance(e, (ast.Attribute, ast.Subscript)):
            name = self.ctx.imports.resolve(dotted(e.value if isinstance(e, ast.Subscript) else e)) or ""
            raw = dotted(e.value if isinstance(e, ast.Subscript) else e) or ""
            if any(name.startswith(p) or raw.startswith(p) for p in spec.SOURCE_PREFIXES):
                return [TraceStep(e.lineno, "source", f"user input {ast.unparse(e)[:80]}")]
            base = self.taint(e.value)
            if base is None and isinstance(e, ast.Subscript):
                return None
            return base
        if isinstance(e, ast.Call):
            return self.call_taint(e)
        if isinstance(e, ast.JoinedStr):
            return self._union(e, [v.value for v in e.values if isinstance(v, ast.FormattedValue)], "f-string")
        if isinstance(e, ast.BinOp):
            return self._union(e, [e.left, e.right], "string concatenation/formatting")
        if isinstance(e, (ast.BoolOp,)):
            return self._union(e, e.values, None)
        if isinstance(e, ast.IfExp):
            return self._union(e, [e.body, e.orelse], None)
        if isinstance(e, (ast.Tuple, ast.List, ast.Set)):
            return self._union(e, e.elts, None)
        if isinstance(e, ast.Dict):
            return self._union(e, [v for v in e.values if v is not None], None)
        if isinstance(e, ast.Starred):
            return self.taint(e.value)
        if isinstance(e, ast.Await):
            return self.taint(e.value)
        return None

    def _union(self, node, parts, how):
        for p in parts:
            t = self.taint(p)
            if t:
                return t + ([TraceStep(node.lineno, "propagate", how)] if how else [])
        return None

    def call_name(self, call):
        return self.ctx.imports.resolve(dotted(call.func))

    def call_taint(self, call: ast.Call) -> Trace | None:
        name = self.call_name(call) or ""
        raw = dotted(call.func) or ""
        if name in spec.SANITIZERS or raw in spec.SANITIZERS:
            return None
        if name in spec.SOURCE_CALLS or any(name.startswith(p) or raw.startswith(p) for p in spec.SOURCE_PREFIXES):
            return [TraceStep(call.lineno, "source", f"user input {ast.unparse(call)[:80]}")]
        callee = self.ctx.lookup(name)
        if callee is not None:
            s = self.ctx.summaries.get(callee)
            if s is None:
                return None
            if s.ret_source:
                return s.ret_source + [TraceStep(call.lineno, "call", f"returned from {callee}()")]
            for i in s.ret_params:
                if i < len(call.args):
                    t = self.taint(call.args[i])
                    if t:
                        return t + [TraceStep(call.lineno, "call", f"passes through {callee}()")]
            return None
        # unknown / library call: conservative propagation from receiver and arguments
        parts = ([call.func.value] if isinstance(call.func, ast.Attribute) else []) + list(call.args) + \
                [k.value for k in call.keywords]
        return self._union(call, parts, f"via {raw or 'call'}()")

    # ---------- sinks ----------
    def check_call(self, call: ast.Call):
        name = self.call_name(call) or ""
        method = call.func.attr if isinstance(call.func, ast.Attribute) else None

        def arg(idx, kw):
            if idx is not None and idx < len(call.args):
                return call.args[idx]
            return next((k.value for k in call.keywords if k.arg == kw), None)

        if name in spec.SINKS:
            cwe, title, idx, kw = spec.SINKS[name]
            a = arg(idx, kw)
            t = self.taint(a)
            if name == "open" or name == "builtins.open":
                mode = arg(1, "mode")
                title = "Path traversal" + (" (write)" if isinstance(mode, ast.Constant) and "w" in str(mode.value) else "")
            if t:
                self.report(call, cwe, title, t)
                if t[0].kind == "param" and name in spec.ALWAYS_UNSAFE_DESERIALIZERS:
                    self.report(call, cwe, title, None, confidence=0.45)
            elif name in spec.ALWAYS_UNSAFE_DESERIALIZERS:
                self.report(call, cwe, title, None, confidence=0.45)
            elif name in ("eval", "exec") and a is not None and not isinstance(a, ast.Constant):
                self.report(call, cwe, title, None, confidence=0.35)
        elif name in ("yaml.load", "yaml.load_all"):
            loader = arg(1, "Loader")
            ln = dotted(loader) or "" if loader is not None else ""
            if not ln.endswith(("SafeLoader", "CSafeLoader", "BaseLoader")):
                self.report(call, "CWE-502", "Insecure deserialization (yaml.load without SafeLoader)",
                            self.taint(arg(0, "stream")), confidence=0.5)
        elif name in spec.SUBPROCESS_SHELL:
            shell = next((k.value for k in call.keywords if k.arg == "shell"), None)
            a = arg(0, "args")
            t = self.taint(a)
            if isinstance(shell, ast.Constant) and shell.value is True:
                if t:
                    self.report(call, "CWE-78", "OS command injection (shell=True)", t)
                elif a is not None and (self._dynamic_string(a) or (isinstance(a, ast.Name) and a.id not in self.sanitized)):
                    self.report(call, "CWE-78", "Subprocess with shell=True and dynamic command", None, confidence=0.3)
            elif t and isinstance(a, (ast.List, ast.Tuple)) and a.elts and self.taint(a.elts[0]):
                self.report(call, "CWE-78", "OS command injection (attacker-controlled executable)", t)
        elif method in spec.SQL_METHODS and call.args:
            q = call.args[0]
            t = self.taint(q)
            if t:
                self.report(call, "CWE-89", "SQL injection", t)
            elif self._dynamic_string(q):
                self.report(call, "CWE-89", "SQL query built with string formatting", None, confidence=0.35)

        # inter-procedural: tainted argument into a function whose parameter reaches a sink
        callee = self.ctx.lookup(name)
        if callee is not None and callee in self.ctx.summaries:
            fi = self.ctx.funcs[callee]
            offset = 1 if fi.params[:1] in (["self"], ["cls"]) and isinstance(call.func, ast.Attribute) else 0
            for i, sinks in self.ctx.summaries[callee].sink_params.items():
                j = i - offset
                if 0 <= j < len(call.args):
                    t = self.taint(call.args[j])
                    if t:
                        for cwe, title, line, ctrace in sinks:
                            self.report(call, cwe, title, t + [TraceStep(call.lineno, "call", f"passed to {callee}()")] + ctrace[1:],
                                        at_line=line, at_func=callee)

    def _is_sanitized(self, e) -> bool:
        if isinstance(e, ast.Constant):
            return True
        if isinstance(e, ast.Call):
            n = self.call_name(e) or ""
            return n in spec.SANITIZERS or (dotted(e.func) or "") in spec.SANITIZERS
        if isinstance(e, ast.Name):
            return e.id in self.sanitized
        if isinstance(e, ast.Tuple):
            return all(self._is_sanitized(x) for x in e.elts)
        return False

    def _dynamic_parts(self, e) -> list:
        if isinstance(e, ast.JoinedStr):
            return [v.value for v in e.values if isinstance(v, ast.FormattedValue)]
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Mod, ast.Add)):
            return self._dynamic_parts(e.left) + self._dynamic_parts(e.right) if not isinstance(e.right, ast.Tuple) \
                else self._dynamic_parts(e.left) + list(e.right.elts)
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format":
            return list(e.args) + [k.value for k in e.keywords]
        if isinstance(e, ast.Constant):
            return []
        return [e]

    def _dynamic_string(self, e):
        """True if e is a string built from non-constant, non-sanitized values."""
        if isinstance(e, ast.Name):
            return e.id in self.ctx.dynamic_strings.get(self.qualname, set())
        if not isinstance(e, (ast.JoinedStr, ast.BinOp, ast.Call)):
            return False
        if isinstance(e, ast.Call) and not (isinstance(e.func, ast.Attribute) and e.func.attr == "format"):
            return False
        return any(not self._is_sanitized(p) for p in self._dynamic_parts(e))

    def report(self, call, cwe, title, trace, confidence=None, at_line=None, at_func=None):
        if trace and trace[0].kind == "param":
            idx = next((i for i, p in enumerate(self.params) if f"'{p}'" in trace[0].detail), None)
            if idx is not None:
                self.summary.sink_params.setdefault(idx, []).append(
                    (cwe, title, at_line or call.lineno, trace + [TraceStep(at_line or call.lineno, "sink", title)]))
            return
        line = at_line or call.lineno
        steps = (trace or []) + [TraceStep(line, "sink", f"{title} at {ast.unparse(call.func)[:60]}()")]
        self.ctx.emit(Finding(rule_id=f"VS-{cwe}", cwe=cwe, title=title, file=self.ctx.filename, line=line,
                              col=call.col_offset, snippet=self.ctx.line(line), function=at_func or self.qualname,
                              tainted=bool(trace), trace=steps,
                              confidence=confidence if confidence is not None else (0.85 if trace else 0.4)))

    # ---------- statements ----------
    def assign(self, target, t: Trace | None, line):
        if isinstance(target, ast.Name):
            if t:
                self.env[target.id] = t + [TraceStep(line, "propagate", f"assigned to '{target.id}'")]
            else:
                self.env.pop(target.id, None)
        elif isinstance(target, (ast.Tuple, ast.List)):
            for el in target.elts:
                self.assign(el, t, line)
        elif isinstance(target, (ast.Attribute, ast.Subscript)) and t:
            base = target.value
            while isinstance(base, (ast.Attribute, ast.Subscript)):
                base = base.value
            if isinstance(base, ast.Name):
                self.env[base.id] = t + [TraceStep(line, "propagate", f"stored into {ast.unparse(target)[:40]}")]

    def run(self):
        self.ctx.dynamic_strings[self.qualname] = set()
        self.block(self.node.body)
        return self.summary

    def block(self, stmts):
        for s in stmts:
            self.stmt(s)

    def calls_in(self, node):
        stack = [node]
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)) and n is not node:
                continue
            if isinstance(n, ast.Call):
                yield n
            stack.extend(ast.iter_child_nodes(n))

    def stmt(self, s):
        if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            return
        if isinstance(s, (ast.If, ast.While)):
            for c in self.calls_in(s.test):
                self.check_call(c)
            self.block(s.body)
            self.block(s.orelse)
            return
        if isinstance(s, (ast.For, ast.AsyncFor)):
            for c in self.calls_in(s.iter):
                self.check_call(c)
            self.assign(s.target, self.taint(s.iter), s.lineno)
            self.block(s.body)
            self.block(s.orelse)
            return
        if isinstance(s, (ast.With, ast.AsyncWith)):
            for it in s.items:
                for c in self.calls_in(it.context_expr):
                    self.check_call(c)
                if it.optional_vars is not None:
                    self.assign(it.optional_vars, self.taint(it.context_expr), s.lineno)
            self.block(s.body)
            return
        if isinstance(s, ast.Try):
            self.block(s.body)
            for h in s.handlers:
                self.block(h.body)
            self.block(s.orelse)
            self.block(s.finalbody)
            return
        for c in self.calls_in(s):
            self.check_call(c)
        if isinstance(s, ast.Assign):
            t = self.taint(s.value)
            for tg in s.targets:
                if isinstance(tg, ast.Name):
                    (self.sanitized.add if self._is_sanitized(s.value) and not isinstance(s.value, ast.Constant)
                     else self.sanitized.discard)(tg.id)
                self.assign(tg, t, s.lineno)
                if isinstance(tg, ast.Name) and self._dynamic_string(s.value):
                    self.ctx.dynamic_strings[self.qualname].add(tg.id)
        elif isinstance(s, ast.AnnAssign) and s.value is not None:
            self.assign(s.target, self.taint(s.value), s.lineno)
        elif isinstance(s, ast.AugAssign):
            t = self.taint(s.value) or self.taint(s.target)
            self.assign(s.target, t, s.lineno)
        elif isinstance(s, ast.Return) and s.value is not None:
            # inspect every tainted name in the return expression (a union keeps only the first trace)
            for n in [s.value] + [x for x in ast.walk(s.value) if isinstance(x, (ast.Name, ast.Call, ast.Attribute, ast.Subscript))]:
                t = self.taint(n)
                if not t:
                    continue
                if t[0].kind == "param":
                    for i, p in enumerate(self.params):
                        if f"'{p}'" in t[0].detail:
                            self.summary.ret_params.add(i)
                elif self.summary.ret_source is None:
                    self.summary.ret_source = t


class ModuleContext:
    def __init__(self, source: str, filename: str):
        self.source, self.filename = source, filename
        self.lines = source.splitlines()
        self.tree = ast.parse(source, filename=filename)
        self.imports = ImportMap(self.tree)
        self.funcs = index_functions(self.tree, self.imports)
        self.by_name = {}
        for q in self.funcs:
            self.by_name.setdefault(q.split(".")[-1], q)
        self.summaries: dict[str, Summary] = {}
        self.dynamic_strings: dict[str, set] = {}
        self._findings: dict[tuple, Finding] = {}
        self.collect = False

    def line(self, n):
        return self.lines[n - 1].strip() if 0 < n <= len(self.lines) else ""

    def lookup(self, name):
        if not name:
            return None
        if name in self.funcs:
            return name
        short = name.split(".")[-1]
        if "." in name and not name.split(".")[0] in ("self", "cls"):
            return None
        return self.by_name.get(short)

    def emit(self, f: Finding):
        if self.collect:
            k = (f.line, f.cwe)
            if k not in self._findings or (f.tainted and not self._findings[k].tainted):
                self._findings[k] = f

    def analyze(self, rounds: int = 3) -> list[Finding]:
        for r in range(rounds + 1):
            self.collect = r == rounds
            for q, fi in self.funcs.items():
                self.summaries[q] = _FunctionAnalyzer(self, q, fi.node, fi.params, _is_route(fi.decorators)).run()
            mod = ast.Module(body=[s for s in self.tree.body], type_ignores=[])
            mod.lineno = 1
            _FunctionAnalyzer(self, "<module>", mod, [], False).run()
        return sorted(self._findings.values(), key=lambda f: f.line)


def analyze_source(source: str, filename: str = "<string>") -> list[Finding]:
    return ModuleContext(source, filename).analyze()
