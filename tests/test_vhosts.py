"""Tests for vhosts.py — nine-manage-vhosts wrapper."""

import pytest
from conftest import HOSTILE_PATHS
from shellparse import argv, sh_words_after

from nine_manage_anubis.runner import FakeRunner
from nine_manage_anubis.vhosts import (
    create_vhost,
    update_vhost,
    remove_vhost,
    create_origin_vhost,
    remove_origin_vhost,
    switch_to_proxy,
    switch_to_default,
    list_certificates,
    certificate_exists,
    create_certificate,
    remove_certificate,
    create_user,
    remove_user,
    list_users,
    user_exists,
    webserver_reload,
    CERTIFICATE_TIMEOUT,
    VHOST_TIMEOUT,
    PROXY_TEMPLATE,
    ORIGIN_TEMPLATE,
    DEFAULT_LE_TEMPLATE,
)

CERT_LIST_OUTPUT = """www.example.ch
================
       DOMAIN: www.example.ch
  VALID UNTIL: 2026-10-28

app.example.ch
================
       DOMAIN: app.example.ch
  VALID UNTIL: 2026-04-27
"""

USERS_JSON = """[{"name": "www-data"}, {"name": "www-anubis"}, {"name": "www-example"}]"""


# --- Vhost operations ---------------------------------------------------------


def test_create_vhost_basic():
    r = FakeRunner()
    create_vhost("example.com", "www-example", runner=r)
    assert "virtual-host create example.com" in r.calls[0]
    assert "--user=www-example" in r.calls[0]
    assert "--template=default" in r.calls[0]


def test_create_vhost_with_webroot_and_vars():
    r = FakeRunner()
    create_vhost(
        "origin-example.com",
        "www-example",
        template=ORIGIN_TEMPLATE,
        webroot="/home/www-example/example.com",
        template_variables={"PHP_VERSION": "8.2"},
        runner=r,
    )
    cmd = r.calls[0]
    assert "--template=default_snakeoil_https" in cmd
    assert "--webroot=/home/www-example/example.com" in cmd
    assert "--template-variable=PHP_VERSION=8.2" in cmd


def test_update_vhost():
    r = FakeRunner()
    update_vhost("example.com", template=PROXY_TEMPLATE,
                 template_variables={"PROXYPORT": "7010"}, runner=r)
    cmd = r.calls[0]
    assert "virtual-host update example.com" in cmd
    assert "--template=proxy_letsencrypt_https_redirect" in cmd
    assert "--template-variable=PROXYPORT=7010" in cmd


def test_remove_vhost():
    r = FakeRunner()
    remove_vhost("origin-example.com", runner=r)
    assert "virtual-host remove origin-example.com" in r.calls[0]


def test_create_origin_vhost():
    r = FakeRunner()
    create_origin_vhost("example.com", "www-example", "/home/www-example/example.com",
                        php_version="8.2", runner=r)
    cmd = r.calls[0]
    assert "origin-example.com" in cmd
    assert "--template=default_snakeoil_https" in cmd
    assert "--webroot=/home/www-example/example.com" in cmd
    assert "PHP_VERSION=8.2" in cmd


def test_create_origin_vhost_no_php():
    r = FakeRunner()
    create_origin_vhost("example.com", "www-example", "/home/www-example/example.com", runner=r)
    assert "PHP_VERSION" not in r.calls[0]


def test_remove_origin_vhost():
    r = FakeRunner()
    remove_origin_vhost("example.com", runner=r)
    assert "remove origin-example.com" in r.calls[0]


def test_switch_to_proxy():
    r = FakeRunner()
    switch_to_proxy("example.com", 7010, runner=r)
    cmd = r.calls[0]
    assert "--template=proxy_letsencrypt_https_redirect" in cmd
    assert "PROXYPORT=7010" in cmd


def test_switch_to_default():
    r = FakeRunner()
    switch_to_default("example.com", runner=r)
    assert "--template=default_letsencrypt_https" in r.calls[0]


# --- Certificate operations ---------------------------------------------------


def test_list_certificates():
    r = FakeRunner({"sudo nine-manage-vhosts certificate list": CERT_LIST_OUTPUT})
    certs = list_certificates(r)
    assert "www.example.ch" in certs
    assert certs["www.example.ch"] == "2026-10-28"
    assert certs["app.example.ch"] == "2026-04-27"


def test_certificate_exists_true():
    r = FakeRunner({"sudo nine-manage-vhosts certificate list": CERT_LIST_OUTPUT})
    assert certificate_exists("app.example.ch", r)


def test_certificate_exists_false():
    r = FakeRunner({"sudo nine-manage-vhosts certificate list": CERT_LIST_OUTPUT})
    assert not certificate_exists("nonexistent.com", r)


def test_create_certificate():
    r = FakeRunner()
    create_certificate("example.com", runner=r)
    assert "certificate create --virtual-host=example.com" in r.calls[0]


def test_remove_certificate():
    r = FakeRunner()
    remove_certificate("example.com", runner=r)
    assert "certificate remove --virtual-host=example.com" in r.calls[0]


# --- User operations ----------------------------------------------------------


def test_list_users():
    r = FakeRunner({"sudo nine-manage-vhosts user list --json": USERS_JSON})
    users = list_users(r)
    assert len(users) == 3
    assert users[1]["name"] == "www-anubis"


def test_user_exists_true():
    r = FakeRunner({"sudo nine-manage-vhosts user list --json": USERS_JSON})
    assert user_exists("www-anubis", r)


def test_user_exists_false():
    r = FakeRunner({"sudo nine-manage-vhosts user list --json": USERS_JSON})
    assert not user_exists("www-nonexistent", r)


def test_create_user():
    r = FakeRunner()
    create_user("www-anubis", runner=r)
    assert "user create www-anubis --no-password" in r.calls[0]


def test_remove_user():
    r = FakeRunner()
    remove_user("www-anubis", runner=r)
    assert "user remove www-anubis" in r.calls[0]


# --- Quoting -------------------------------------------------------------------
#
# Domains and users clear a whitelist before they get here, but webroots and
# template variables do not: nine-manage-vhosts reports whatever the operator
# configured, and a template variable is an arbitrary key/value pair. So the
# command these functions build is asserted word-for-word, as a shell would
# split it — a value that escaped its quotes shows up as several words.


@pytest.mark.parametrize("webroot", HOSTILE_PATHS)
def test_create_vhost_quotes_a_hostile_webroot(webroot):
    r = FakeRunner()
    create_vhost("example.com", "www-example", webroot=webroot, runner=r)
    assert f"--webroot={webroot}" in argv(r.calls[0])


@pytest.mark.parametrize("webroot", HOSTILE_PATHS)
def test_create_vhost_hands_a_real_shell_one_webroot_argument(webroot):
    # shlex splits and unquotes but never expands, so it cannot tell whether a
    # `$( )` would have run. A real /bin/sh can.
    r = FakeRunner()
    create_vhost("example.com", "www-example", webroot=webroot, runner=r)
    words = sh_words_after(r.calls[0], "sudo nine-manage-vhosts virtual-host create ")
    assert f"--webroot={webroot}" in words
    assert len(words) == 4  # domain, --user, --template, --webroot


@pytest.mark.parametrize("webroot", HOSTILE_PATHS)
def test_create_origin_vhost_quotes_a_hostile_webroot(webroot):
    r = FakeRunner()
    create_origin_vhost("example.com", "www-example", webroot, runner=r)
    assert f"--webroot={webroot}" in argv(r.calls[0])


HOSTILE_TEMPLATE_VARIABLES = [
    ("PHP_VERSION", "8.2; id"),
    ("PHP_VERSION", "8.2`id`"),
    ("PHP_VERSION", "8.2$(id)"),
    ("PHP_VERSION", "8 2"),
    ("PHP_VERSION", "it's 8.2"),
    ("PHP VERSION", "8.2"),
    ("PHP_VERSION`id`", "8.2"),
]


@pytest.mark.parametrize("key,value", HOSTILE_TEMPLATE_VARIABLES)
def test_create_vhost_quotes_a_hostile_template_variable(key, value):
    r = FakeRunner()
    create_vhost("example.com", "www-example", template_variables={key: value}, runner=r)
    assert f"--template-variable={key}={value}" in argv(r.calls[0])


@pytest.mark.parametrize("key,value", HOSTILE_TEMPLATE_VARIABLES)
def test_create_vhost_hands_a_real_shell_one_template_variable_argument(key, value):
    r = FakeRunner()
    create_vhost("example.com", "www-example", template_variables={key: value}, runner=r)
    words = sh_words_after(r.calls[0], "sudo nine-manage-vhosts virtual-host create ")
    assert f"--template-variable={key}={value}" in words
    assert len(words) == 4  # domain, --user, --template, --template-variable


@pytest.mark.parametrize("key,value", HOSTILE_TEMPLATE_VARIABLES)
def test_update_vhost_quotes_a_hostile_template_variable(key, value):
    r = FakeRunner()
    update_vhost("example.com", template_variables={key: value}, runner=r)
    assert f"--template-variable={key}={value}" in argv(r.calls[0])


def test_create_vhost_quotes_domain_user_and_template():
    r = FakeRunner()
    create_vhost("example.com; id", "www example", template="tpl`id`", runner=r)
    words = argv(r.calls[0])
    assert "example.com; id" in words
    assert "--user=www example" in words
    assert "--template=tpl`id`" in words


@pytest.mark.parametrize(
    "call", [remove_vhost, remove_origin_vhost, switch_to_default]
)
def test_domain_only_functions_quote_the_domain(call):
    r = FakeRunner()
    call("example.com; id", runner=r)
    words = argv(r.calls[0])
    assert any(w.endswith("example.com; id") for w in words)
    assert "id" not in words


def test_certificate_functions_quote_the_domain():
    r = FakeRunner()
    create_certificate("example.com; id", runner=r)
    assert "--virtual-host=example.com; id" in argv(r.calls[0])
    r = FakeRunner()
    remove_certificate("example.com; id", runner=r)
    assert "--virtual-host=example.com; id" in argv(r.calls[0])


@pytest.mark.parametrize("call", [create_user, remove_user])
def test_user_functions_quote_the_name(call):
    r = FakeRunner()
    call("www example`id`", runner=r)
    assert "www example`id`" in argv(r.calls[0])


def test_switch_to_proxy_passes_the_port_as_a_word():
    r = FakeRunner()
    switch_to_proxy("example.com", 7010, runner=r)
    assert "--template-variable=PROXYPORT=7010" in argv(r.calls[0])


def test_no_notify_stays_a_flag():
    r = FakeRunner()
    create_vhost("example.com", "www-example", no_notify=True, runner=r)
    assert "--no-notify-services" in argv(r.calls[0])


# --- Timeouts -----------------------------------------------------------------
#
# A vhost change reloads Apache and a certificate request talks to Let's
# Encrypt, so both are slower than an ordinary command — but neither may run
# without a limit.


@pytest.mark.parametrize(
    "call,args",
    [
        (create_vhost, ("example.com", "www-example")),
        (update_vhost, ("example.com",)),
        (remove_vhost, ("example.com",)),
        (webserver_reload, ()),
    ],
)
def test_a_vhost_change_runs_under_the_vhost_timeout(call, args):
    r = FakeRunner()
    call(*args, runner=r)
    assert r.invocations[0].timeout == VHOST_TIMEOUT


def test_a_certificate_request_gets_longer_and_names_the_domain():
    r = FakeRunner()
    create_certificate("example.com", runner=r)
    assert r.invocations[0].timeout == CERTIFICATE_TIMEOUT
    assert "example.com" in r.invocations[0].what


def test_a_read_only_query_names_what_it_was_reading():
    r = FakeRunner({"sudo nine-manage-vhosts user list --json": "[]"})
    list_users(r)
    assert r.invocations[0].what
