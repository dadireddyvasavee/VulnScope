"""AST helpers: import-alias resolution, dotted call names, function index and call graph."""
from __future__ import annotations
import ast
from dataclasses import dataclass, field


def dotted(node) -> str | None:
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    elif isinstance(node, ast.Call):
        inner = dotted(node.func)
        if inner is None:
            return None
        parts.append(inner + "()")
    else:
        return None
    return ".".join(reversed(parts))


class ImportMap:
    def __init__(self, tree: ast.AST):
        self.alias: dict[str, str] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    self.alias[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    self.alias[a.asname or a.name] = f"{n.module}.{a.name}"

    def resolve(self, name: str | None) -> str | None:
        if not name:
            return name
        head, _, rest = name.partition(".")
        full = self.alias.get(head, head)
        return f"{full}.{rest}" if rest else full


@dataclass
class FunctionInfo:
    name: str
    qualname: str
    node: ast.FunctionDef
    params: list[str]
    calls: set[str] = field(default_factory=set)
    decorators: list[str] = field(default_factory=list)


def index_functions(tree: ast.AST, imports: ImportMap) -> dict[str, FunctionInfo]:
    out = {}

    def visit(node, prefix=""):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                q = f"{prefix}{child.name}"
                params = [a.arg for a in child.args.posonlyargs + child.args.args + child.args.kwonlyargs]
                fi = FunctionInfo(child.name, q, child, params,
                                  decorators=[imports.resolve(dotted(d.func if isinstance(d, ast.Call) else d)) or "" for d in child.decorator_list])
                for c in ast.walk(child):
                    if isinstance(c, ast.Call):
                        n = imports.resolve(dotted(c.func))
                        if n:
                            fi.calls.add(n)
                out[q] = fi
                visit(child, q + ".")
            elif isinstance(child, ast.ClassDef):
                visit(child, f"{prefix}{child.name}.")
    visit(tree)
    return out


def call_graph(funcs: dict[str, FunctionInfo]) -> dict[str, set[str]]:
    names = {f.name: q for q, f in funcs.items()}
    return {q: {names[c.split(".")[-1]] for c in f.calls if c.split(".")[-1] in names} for q, f in funcs.items()}
