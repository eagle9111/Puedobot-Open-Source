"""Tests covering AST and Bandit SAST detection engines."""
import os
import pytest

from app.engine.ast_parser import scan_file_for_hotspots
from app.engine.bandit_scanner import scan_file_with_bandit
from app.engine.scanner import scan_file


CORPUS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "benchmarks", "corpus")


def test_ast_sql_injection_detected(tmp_path):
    """Verify raw formatted SQL queries are flagged by AST scanner."""
    code = """
import sqlite3
def get_user(name):
    cur = sqlite3.connect("db.sqlite").cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
"""
    test_file = tmp_path / "test_sql.py"
    test_file.write_text(code, encoding="utf-8")
    nodes = scan_file_for_hotspots(str(test_file))
    flagged = [n for n in nodes if "execute" in n.function_name]
    assert len(flagged) >= 1
    assert any("SELECT" in n.code_context for n in flagged)


def test_ast_command_injection_detected(tmp_path):
    """Verify os.system call is flagged by AST scanner."""
    code = """
import os
def backup(path):
    os.system("tar czf /tmp/b.tgz " + path)
"""
    test_file = tmp_path / "test_cmd.py"
    test_file.write_text(code, encoding="utf-8")
    nodes = scan_file_for_hotspots(str(test_file))
    flagged = [n for n in nodes if "os.system" in n.function_name]
    assert len(flagged) >= 1


def test_ast_eval_and_exec_detected(tmp_path):
    """Verify eval and exec sinks are flagged by AST scanner."""
    code = """
def run_dynamic(expr, stmts):
    eval(expr)
    exec(stmts)
"""
    test_file = tmp_path / "test_dynamic.py"
    test_file.write_text(code, encoding="utf-8")
    nodes = scan_file_for_hotspots(str(test_file))
    funcs = [n.function_name for n in nodes]
    assert "eval" in funcs
    assert "exec" in funcs


def test_bandit_weak_crypto_md5_flagged(tmp_path):
    """Verify Bandit flags MD5 usage without usedforsecurity=False."""
    code = """
import hashlib
def hash_pw(pw):
    return hashlib.md5(pw.encode()).hexdigest()
"""
    test_file = tmp_path / "test_crypto.py"
    test_file.write_text(code, encoding="utf-8")
    nodes = scan_file_with_bandit(str(test_file))
    assert any("B324" in n.function_name or "md5" in n.function_name.lower() or "B303" in n.function_name for n in nodes)


def test_bandit_insecure_random_flagged(tmp_path):
    """Verify Bandit flags standard random module used for tokens."""
    code = """
import random
def token():
    return str(random.random())
"""
    test_file = tmp_path / "test_random.py"
    test_file.write_text(code, encoding="utf-8")
    nodes = scan_file_with_bandit(str(test_file))
    assert any("B311" in n.function_name or "random" in n.function_name.lower() for n in nodes)


def test_safe_corpus_files_detection():
    """Verify scanner execution on system_and_crypto corpus file."""
    corpus_file = os.path.join(CORPUS_DIR, "system_and_crypto.py")
    assert os.path.exists(corpus_file)
    hotspots = scan_file(corpus_file)

    funcs = [h.function_name for h in hotspots]
    assert any("os.system" in f for f in funcs)
    assert any("B301" in f or "pickle" in f.lower() for f in funcs)
    assert any("B506" in f or "yaml" in f.lower() for f in funcs)
