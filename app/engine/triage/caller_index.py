"""Conservative lexical caller links; unresolved calls carry no target claim."""
from __future__ import annotations

import ast
import os
from dataclasses import dataclass, field
from typing import Any


@dataclass(eq=False)
class Scope:
    path: str
    kind: str
    parent: Scope | None = None
    bindings: dict[str, Any] = field(default_factory=dict)
    inherited: bool = False

    def define(self, name: str, value: Any) -> None:
        self.bindings[name] = None if name in self.bindings else value

    def lookup(self, name: str):
        if name in self.bindings:
            return self.bindings[name]
        parent = self.parent
        if self.kind == 'function':
            while parent and parent.kind == 'class':
                parent = parent.parent
        return parent.lookup(name) if parent else None


class Symbols(ast.NodeVisitor):
    def __init__(self, path, tree, functions):
        self.module = Scope(path, 'module')
        self.scope = self.module
        self.functions = {(fn.start, fn.name): fn for fn in functions}
        self.calls = []
        self.visit(tree)

    def visit_FunctionDef(self, node):
        start = min([node.lineno] + [dec.lineno for dec in node.decorator_list])
        fn = self.functions[(start, node.name)]
        ancestry, scope = [], self.scope
        while scope.parent:
            ancestry.append(scope.path)
            scope = scope.parent
        fn.qualified_name = '.'.join([*reversed(ancestry), node.name])
        self.scope.define(node.name, ('function', fn))
        # Defaults/decorators execute in the defining scope.
        for expression in [*node.decorator_list, *node.args.defaults, *node.args.kw_defaults]:
            if expression:
                self.visit(expression)
        parent = self.scope
        self.scope = Scope(node.name, 'function', parent)
        args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
        for arg in [*args, node.args.vararg, node.args.kwarg]:
            if arg:
                self.scope.define(arg.arg, None)
        positional = [*node.args.posonlyargs, *node.args.args]
        if (parent.kind == 'class' and not parent.inherited and positional
                and positional[0].arg in {'self', 'cls'}
                and not any(isinstance(dec, ast.Name) and dec.id == 'staticmethod' for dec in node.decorator_list)):
            self.scope.bindings[positional[0].arg] = ('receiver', parent)
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    visit_AsyncFunctionDef = visit_FunctionDef

    def visit_ClassDef(self, node):
        parent = self.scope
        child = Scope(node.name, 'class', parent, inherited=bool(node.bases or node.keywords))
        parent.define(node.name, ('class', child))
        for expression in [*node.bases, *node.decorator_list, *node.keywords]:
            self.visit(expression)
        self.scope = child
        for statement in node.body:
            self.visit(statement)
        self.scope = parent

    def visit_Name(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)):
            self.scope.define(node.id, None)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, (ast.Store, ast.Del)) and isinstance(node.value, ast.Name):
            receiver = self.scope.lookup(node.value.id)
            if receiver and receiver[0] == 'receiver':
                receiver[1].define(node.attr, None)
        self.generic_visit(node)

    def visit_Import(self, node):
        for alias in node.names:
            self.scope.define(alias.asname or alias.name.split('.')[0],
                              ('module', alias.name if alias.asname else alias.name.split('.')[0]))

    def visit_ImportFrom(self, node):
        if any(alias.name == '*' for alias in node.names):
            # Star imports may overwrite any lexical binding in this scope.
            self.scope.bindings['*'] = None
        module = node.module or ''
        for alias in node.names:
            self.scope.define(alias.asname or alias.name, ('import', module, alias.name, node.level))

    def visit_Global(self, node):
        for name in node.names:
            self.scope.bindings[name] = None

    visit_Nonlocal = visit_Global

    def visit_Lambda(self, node):
        # Lambda/comprehension bindings need separate scopes; omit these edges.
        return

    def visit_ListComp(self, node):
        return

    visit_SetComp = visit_ListComp
    visit_DictComp = visit_ListComp
    visit_GeneratorExp = visit_ListComp

    def visit_Call(self, node):
        self.calls.append((node, self.scope))
        self.generic_visit(node)


def build_callers(index, parsed):
    from app.engine.triage.context_builder import CallSite
    modules = {}
    symbol_tables = []
    for path, tree in parsed:
        symbols = Symbols(path, tree, index.functions[path])
        symbol_tables.append((path, symbols))
        relative = os.path.relpath(path, index.root).replace(os.sep, '/')
        module = relative[:-3].replace('/', '.')
        if module == '__init__':
            module = ''
        elif module.endswith('.__init__'):
            module = module[:-9]
        # Conflicting module.py and module/__init__.py are intentionally unresolved.
        modules[module] = symbols.module if module not in modules else None
        symbols.module.path = module

    def resolve(binding, current_module):
        if not binding:
            return None
        if binding[0] == 'function':
            return binding[1]
        if binding[0] == 'import':
            _, module, member, level = binding
            if level:
                parts = current_module.split('.')
                # A package __init__ uses its own module as its package.
                package = parts if current_module in package_modules else parts[:-1]
                if level > len(package):
                    return None
                module = '.'.join([*package[:len(package)-level+1], *([module] if module else [])])
            target = modules.get(module)
            if target and '*' not in target.bindings:
                imported = target.bindings.get(member)
                return imported[1] if imported and imported[0] == 'function' else None
        return None

    package_modules = {symbols.module.path for path, symbols in symbol_tables if os.path.basename(path) == '__init__.py'}
    index.callers.clear()
    for path, symbols in symbol_tables:
        for node, scope in symbols.calls:
            # A star import anywhere in the lexical chain invalidates inference.
            current, uncertain = scope, False
            while current:
                uncertain |= '*' in current.bindings
                current = current.parent
            if uncertain:
                continue
            target = None
            if isinstance(node.func, ast.Name):
                target = resolve(scope.lookup(node.func.id), symbols.module.path)
            elif isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                binding = scope.lookup(node.func.value.id)
                if binding and binding[0] == 'receiver':
                    member = binding[1].bindings.get(node.func.attr)
                    target = resolve(member, symbols.module.path)
                elif binding and binding[0] == 'module':
                    module = modules.get(binding[1])
                    if module and '*' not in module.bindings:
                        target = resolve(module.bindings.get(node.func.attr), binding[1])
            if target:
                identity = target.identity
                site = CallSite(path, node.lineno, index.enclosing_function(path, node.lineno))
                index.callers.setdefault(identity, []).append(site)
