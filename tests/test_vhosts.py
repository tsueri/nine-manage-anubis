"""Tests for vhosts.py — nine-manage-vhosts wrapper."""

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
