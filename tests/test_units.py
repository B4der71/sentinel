"""Unit tests for the deterministic, network-free components."""
from sentinel.crawler.canonicalizer import canonicalize, param_signature
from sentinel.core.scope import Scope, OutOfScopeError
from sentinel.plugins.xss.contexts import classify, Context, make_marker
from sentinel.plugins.sqli.fingerprint import fingerprint_from_error, Dbms
import pytest


def test_canonicalize_sorts_and_normalizes():
    a = canonicalize("http://h/p?b=2&a=1#frag")
    b = canonicalize("http://h:80/p/?a=1&b=2")
    assert a == b == "http://h/p?a=1&b=2"


def test_param_signature_ignores_values():
    assert param_signature("http://h/x?id=1") == param_signature("http://h/x?id=999")


def test_scope_default_deny():
    s = Scope(allowed_hosts={"localhost:8080"})
    assert s.is_in_scope("http://localhost:8080/a")
    assert not s.is_in_scope("http://evil.example/a")
    with pytest.raises(OutOfScopeError):
        s.assert_in_scope("http://evil.example/a")


def test_scope_blocks_gov():
    s = Scope(allowed_hosts={"agency.gov"})
    assert not s.is_in_scope("http://agency.gov/")


def test_xss_context_html_text():
    m = make_marker()
    refl = classify(f"<div>{m}</div>", m)
    assert refl and refl[0].context is Context.HTML_TEXT


def test_xss_context_script():
    m = make_marker()
    refl = classify(f"<script>var x='{m}';</script>", m)
    assert refl and refl[0].context is Context.SCRIPT


def test_xss_no_reflection():
    assert classify("<div>nothing here</div>", make_marker()) == []


def test_sqli_fingerprint():
    assert fingerprint_from_error("You have an error in your SQL syntax; MySQL") is Dbms.MYSQL
    assert fingerprint_from_error("ORA-00933: bad command") is Dbms.ORACLE
    assert fingerprint_from_error("totally normal page") is Dbms.UNKNOWN
