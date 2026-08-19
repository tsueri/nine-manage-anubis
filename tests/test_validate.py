"""Tests for validate.py — the whitelist boundary.

Every domain, system user and version that reaches a privileged command
must pass through here first. These tests are the contract for what is
accepted and what is rejected.
"""

import pytest

from conftest import hostile
from nine_manage_anubis.validate import (
    MAX_DOMAIN_LENGTH,
    MAX_USER_LENGTH,
    PORT_RANGE_END,
    PORT_RANGE_START,
    ValidationError,
    required_vhost_field,
    validate_domain,
    validate_path,
    validate_port,
    validate_filename,
    validate_system_user,
    validate_version,
    validate_vhost_record,
)


# The shared payload set, plus the extra metacharacter shapes that only the
# validators themselves are exercised against.
INJECTIONS = hostile("example.com") + [
    "example.com id",
    "example.com|id",
    "example.com&&id",
    "example.com>out",
    "example.com'",
    'example.com"',
    "example.com\\",
    "example.com*",
    "..",
    "-rf",
]


# --- domain -------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "example.com",
    "sub.example.com",
    "forum.example.ch",
    "origin-test.example.ch",
    "xn--bcher-kva.example",
    "a",
    "1.2.3.4",
])
def test_valid_domains_pass_through(value):
    assert validate_domain(value) == value


@pytest.mark.parametrize("value", INJECTIONS)
def test_domain_rejects_injections(value):
    with pytest.raises(ValidationError):
        validate_domain(value)


@pytest.mark.parametrize("value", [
    "-example.com",       # leading dash — looks like a CLI flag
    "--all",
    "example.com-",       # trailing dash
    ".example.com",       # leading dot
    "example.com.",       # trailing dot
    "example..com",       # empty label
    "-foo.example.com",   # label starting with a dash
    "foo-.example.com",   # label ending with a dash
    "Example.com",        # uppercase not in the accepted charset
    "exämple.com",        # non-ASCII
    "example.com/../etc",
    "a" * 254,            # too long
])
def test_domain_rejects_malformed(value):
    with pytest.raises(ValidationError):
        validate_domain(value)


def test_domain_rejects_non_string():
    with pytest.raises(ValidationError):
        validate_domain(None)


def test_domain_accepts_max_length():
    value = ("a" * 63 + ".") * 3 + "a" * 61
    assert len(value) == 253
    assert validate_domain(value) == value


def test_domain_rejects_over_length_label():
    with pytest.raises(ValidationError):
        validate_domain("a" * 64 + ".com")


def test_domain_error_names_value_and_expected_form():
    with pytest.raises(ValidationError) as exc:
        validate_domain("example.com; id")
    msg = str(exc.value)
    assert "example.com; id" in msg
    assert "domain" in msg
    assert "lowercase" in msg


def test_domain_error_uses_custom_field_name():
    with pytest.raises(ValidationError) as exc:
        validate_domain("bad;domain", field="vhost domain from nine-manage-vhosts")
    assert "vhost domain from nine-manage-vhosts" in str(exc.value)


def test_validation_error_is_a_value_error():
    assert issubclass(ValidationError, ValueError)


# --- system user --------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "www-anubis",
    "www-data",
    "www-example",
    "_svc",
    "a",
    "user_1",
])
def test_valid_users_pass_through(value):
    assert validate_system_user(value) == value


@pytest.mark.parametrize("value", INJECTIONS)
def test_user_rejects_injections(value):
    with pytest.raises(ValidationError):
        validate_system_user(value)


@pytest.mark.parametrize("value", [
    "-user",              # leading dash
    "--all",
    "1user",              # must start with a letter or underscore
    "User",               # uppercase not in the accepted charset
    "www anubis",
    "www/anubis",
    "../../root",
    "u" * 33,             # longer than the useradd limit
])
def test_user_rejects_malformed(value):
    with pytest.raises(ValidationError):
        validate_system_user(value)


def test_user_error_names_value_and_expected_form():
    with pytest.raises(ValidationError) as exc:
        validate_system_user("../../root")
    msg = str(exc.value)
    assert "../../root" in msg
    assert "user" in msg


# --- version ------------------------------------------------------------------


@pytest.mark.parametrize("value", ["1.27.0", "0.0.1", "10.20.30"])
def test_valid_versions_pass_through(value):
    assert validate_version(value) == value


@pytest.mark.parametrize("value", INJECTIONS)
def test_version_rejects_injections(value):
    with pytest.raises(ValidationError):
        validate_version(value)


@pytest.mark.parametrize("value", [
    "v1.27.0",            # no leading v — the caller adds it
    "1.27",
    "1.27.0.1",
    "1.27.0-rc1",
    "1.27.0 ",
    "1.27.0\n",
    "-1.27.0",
    "١.٢.٣",              # non-ASCII digits
    "latest",
])
def test_version_rejects_malformed(value):
    with pytest.raises(ValidationError):
        validate_version(value)


def test_version_error_names_value_and_expected_form():
    with pytest.raises(ValidationError) as exc:
        validate_version("1.27.0; rm -rf /")
    msg = str(exc.value)
    assert "1.27.0; rm -rf /" in msg
    assert "version" in msg


# --- port ---------------------------------------------------------------------


@pytest.mark.parametrize("value", [PORT_RANGE_START, PORT_RANGE_END, 7014, "7010"])
def test_valid_ports_pass_through(value):
    assert validate_port(value) == int(value)


@pytest.mark.parametrize("value", [
    PORT_RANGE_START - 1,
    PORT_RANGE_END + 1,
    0,
    -1,
    80,
    "7010; id",
    "70x0",
    "",
    None,
    7010.5,
])
def test_port_rejects_out_of_range_and_malformed(value):
    with pytest.raises(ValidationError):
        validate_port(value)


def test_port_error_names_value_and_range():
    with pytest.raises(ValidationError) as exc:
        validate_port(80)
    msg = str(exc.value)
    assert "80" in msg
    assert str(PORT_RANGE_START) in msg
    assert str(PORT_RANGE_END) in msg


# --- path ---------------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "/home/www-anubis/.config/anubis/policy.yaml",
    "/etc/anubis/botPolicies.yaml",
    "/home/www-anubis/bin/anubis",
])
def test_valid_paths_pass_through(value):
    assert validate_path(value) == value


@pytest.mark.parametrize("value", [
    "/tmp/policy.yaml; id",
    "/tmp/policy.yaml`id`",
    "/tmp/$(id)/policy.yaml",
    "/tmp/policy.yaml\nid",
    "/tmp/policy yaml",
    "relative/policy.yaml",     # must be absolute
    "/tmp/../etc/passwd",       # no traversal
    "-/tmp/policy.yaml",
    "",
    None,
])
def test_path_rejects_malformed(value):
    with pytest.raises(ValidationError):
        validate_path(value)


def test_path_error_names_value_and_expected_form():
    with pytest.raises(ValidationError) as exc:
        validate_path("/tmp/x; id")
    msg = str(exc.value)
    assert "/tmp/x; id" in msg
    assert "absolute" in msg


# --- filename -----------------------------------------------------------------


@pytest.mark.parametrize("value", [
    "wordfence-waf.php",
    "anubis-origin-shim.php",
    "_x",
    "a.b.c",
])
def test_valid_filenames_pass_through(value):
    assert validate_filename(value) == value


@pytest.mark.parametrize("value", [
    "wordfence-waf.php; id",
    "wordfence-waf.php`id`",
    "$(id).php",
    "waf.php\nid",
    "../wordfence-waf.php",     # escapes the webroot
    "sub/dir/waf.php",          # no separators
    "/etc/passwd",
    "..",
    ".",
    "",
    None,
])
def test_filename_rejects_malformed(value):
    with pytest.raises(ValidationError):
        validate_filename(value)


def test_filename_error_names_value_and_expected_form():
    with pytest.raises(ValidationError) as exc:
        validate_filename("../waf.php")
    msg = str(exc.value)
    assert "../waf.php" in msg
    assert "file name" in msg


# --- vhost record -------------------------------------------------------------


def test_valid_vhost_record_passes_through():
    record = {
        "domain": "example.ch",
        "user": "www-example",
        "webroot": "/home/www-example/example.ch",
        "template": "proxy_letsencrypt_https_redirect",
        "template_variables": {"PROXYPORT": "7014", "PHP_VERSION": "8.2"},
    }
    assert validate_vhost_record(record) is record


def test_vhost_record_accepts_a_proxyport_outside_the_anubis_range():
    """A vhost may proxy to some other application entirely."""
    record = {
        "domain": "app.example.com",
        "template_variables": {"PROXYPORT": "3000"},
    }
    assert validate_vhost_record(record) is record


@pytest.mark.parametrize("record", [
    {"domain": "evil.com; id"},
    {"domain": "example.com", "user": "www-x`id`"},
    {"domain": "example.com", "webroot": "/home/x; id"},
    {"domain": "example.com", "template_variables": {"PROXYPORT": "70x0"}},
    {"domain": "example.com", "template_variables": {"PROXYPORT": "99999"}},
    {"domain": "example.com", "template_variables": {"PHP_VERSION": "8.2; id"}},
    {},
    "not a dict",
    None,
])
def test_vhost_record_rejects_malformed(record):
    with pytest.raises(ValidationError):
        validate_vhost_record(record)


def test_user_length_limit_comes_from_the_documented_constant():
    """MAX_USER_LENGTH must be load-bearing, not decoration."""
    assert validate_system_user("u" * MAX_USER_LENGTH) == "u" * MAX_USER_LENGTH
    with pytest.raises(ValidationError):
        validate_system_user("u" * (MAX_USER_LENGTH + 1))


def test_domain_length_limit_comes_from_the_documented_constant():
    with pytest.raises(ValidationError):
        validate_domain("a" * (MAX_DOMAIN_LENGTH + 1))


# --- A field the vhost list did not report ------------------------------------
#
# A webroot, a user or a template is read straight off the JSON and used to
# build a command. Indexing the dict for it turns an unexpected shape — or an
# upstream change — into a bare KeyError, which tells an operator nothing.


def test_required_field_returns_the_value():
    record = {"domain": "example.com", "webroot": "/home/www-example/example.com"}
    assert required_vhost_field(record, "webroot") == "/home/www-example/example.com"


@pytest.mark.parametrize("record", [
    {"domain": "example.com"},
    {"domain": "example.com", "webroot": None},
])
def test_missing_required_field_names_the_vhost_and_the_field(record):
    with pytest.raises(ValidationError) as exc:
        required_vhost_field(record, "webroot")
    assert "example.com" in str(exc.value)
    assert "webroot" in str(exc.value)


def test_missing_required_field_on_a_nameless_record_still_reports():
    with pytest.raises(ValidationError) as exc:
        required_vhost_field({}, "template")
    assert "template" in str(exc.value)


def test_a_required_field_of_the_wrong_type_is_rejected():
    """An upstream shape change is a message, not a command built round a dict."""
    with pytest.raises(ValidationError) as exc:
        required_vhost_field({"domain": "example.com", "webroot": {"path": "/x"}}, "webroot")
    assert "example.com" in str(exc.value)
    assert "webroot" in str(exc.value)
