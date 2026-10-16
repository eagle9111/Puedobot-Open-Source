"""Qualified caller edges never conflate unrelated short method names."""
from app.engine.triage.context_builder import RepoIndex, build_extended_context
from app.schemas.node import SuspiciousNode


def write(tmp_path, name, source):
    file = tmp_path/name
    file.parent.mkdir(parents=True, exist_ok=True)
    file.write_text(source)
    return str(file)


def edges(index, path, name):
    fn = next(fn for fn in index.functions[path] if fn.qualified_name == name)
    return [(site.file, site.caller.qualified_name if site.caller else None) for site in index.callers.get(fn.identity, [])]


def test_two_classes_same_method_and_unknown_receiver(tmp_path):
    path = write(tmp_path, 'classes.py', '''class A:
    def execute(self): pass
    def call(self): self.execute()
class B:
    def execute(self): pass
    def call(self): self.execute()
def unknown(receiver): receiver.execute()
''')
    index = RepoIndex(str(tmp_path))
    assert edges(index, path, 'A.execute') == [(path, 'A.call')]
    assert edges(index, path, 'B.execute') == [(path, 'B.call')]


def test_module_imports_aliases_and_lexical_shadowing(tmp_path):
    first = write(tmp_path, 'first.py', 'def sink(): pass\ndef call(): sink()\n')
    second = write(tmp_path, 'second.py', 'def sink(): pass\ndef call(): sink()\n')
    caller = write(tmp_path, 'entry.py', '''import first as chosen
from second import sink as other
def route():
    chosen.sink()
    other()
def shadow(sink): sink()
def nested():
    def sink(): pass
    sink()
''')
    index = RepoIndex(str(tmp_path))
    assert sorted(edges(index, first, 'sink')) == sorted([(first, 'call'), (caller, 'route')])
    assert sorted(edges(index, second, 'sink')) == sorted([(second, 'call'), (caller, 'route')])
    assert sorted(edges(index, caller, 'nested.sink')) == sorted([(caller, 'nested')])


def test_reassignments_inheritance_star_import_and_unknown_bindings_are_omitted(tmp_path):
    path = write(tmp_path, 'uncertain.py', '''def sink(): pass
def caller(): sink()
sink = unknown
class Base:
    def sink(self): pass
class Child(Base):
    def call(self): self.sink()
class Local:
    def sink(self): pass
    def call(self):
        self.sink = unknown
        self.sink()
''')
    star = write(tmp_path, 'star.py', 'from unknown import *\ndef sink(): pass\ndef call(): sink()\n')
    index = RepoIndex(str(tmp_path))
    assert edges(index, path, 'sink') == []
    assert edges(index, path, 'Base.sink') == []
    assert edges(index, path, 'Local.sink') == []
    assert edges(index, star, 'sink') == []


def test_relative_import_async_and_prompt_uncertainty(tmp_path):
    write(tmp_path, 'pkg/__init__.py', '')
    target = write(tmp_path, 'pkg/target.py', 'async def sink(): pass\n')
    caller = write(tmp_path, 'pkg/entry.py', 'from .target import sink as alias\nasync def route(): await alias()\n')
    index = RepoIndex(str(tmp_path))
    assert edges(index, target, 'sink') == [(caller, 'route')]
    context = build_extended_context(SuspiciousNode(target, 1, 'sink', 'pass'), index)
    assert 'route' in context
    assert 'ATTACKER-CONTROLLED' not in context
