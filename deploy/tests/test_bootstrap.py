"""Non-socket bootstrap checks; synthetic state is confined to pytest tmp_path."""
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import sqlite3
import ssl

import pytest

from controller.service import Broker
from deploy.bootstrap import bundle, initialize, launch
from deploy.state_guard import MountObservation, StateGuardError, StatePolicy

REPOSITORY = Path(__file__).resolve().parents[2]


@pytest.fixture
def config():
    return {"schema_version": 1, "mode": "synthetic", "account": "123456789012",
            "region": "us-east-1", "installation": {"schema_version": 1, "project_id": "synthetic-bootstrap", "account_id": "123456789012", "region": "us-east-1", "limit_microusd": 200_000_000}, "controller_private_ipv4": "10.78.0.10",
            "controller_private_dns": "controller.agent-controller.internal",
            "controller_uid": 42010, "controller_gid": 42010,
            "proxy_uid": 42011, "proxy_gid": 42011,
            "python_version": "3.12.14", "nginx_version": "1.26.3",
            "python_sha256": "a" * 64, "nginx_sha256": "b" * 64,
            "state_policy": {"mountpoint": "/srv/controller-volume",
                "state_dir": "/srv/controller-volume/controller",
                "volume_id": "vol-0123456789abcdef0",
                "filesystem_uuid": "12345678-1234-1234-1234-123456789abc",
                "uid": 42010, "gid": 42010}}


@pytest.fixture(scope="module")
def public_ca():
    # Existing public trust store only: no generated certificate/private key.
    text = Path(ssl.get_default_verify_paths().cafile).read_text()
    return bundle.PEM_CERT.findall(text)[0]


@pytest.mark.parametrize("change", [
    {"mode": "live"}, {"account": "000000000000"}, {"region": "us-west-2"},
    {"controller_private_ipv4": "127.0.0.1"}, {"controller_private_ipv4": "8.8.8.8"},
    {"controller_private_ipv4": "0.0.0.0"}, {"controller_private_ipv4": "169.254.169.254"},
    {"controller_private_dns": "safe.internal;\ninclude /evil;"},
    {"proxy_uid": 42010}, {"controller_uid": True}, {"proxy_gid": 42010},
    {"python_sha256": "0" * 64}, {"nginx_version": None}, {"unexpected": True},
])
def test_invalid_target_injection_or_identity_is_rejected(config, change):
    config.update(change)
    with pytest.raises(bundle.BootstrapError):
        bundle.validate_config(config)


def test_policy_cannot_redirect_state_or_borrow_other_identity(config):
    for changes in ({"state_dir": "/srv/controller-volume/other"}, {"uid": 42011},
                    {"mountpoint": "/"}):
        changed = deepcopy(config)
        changed["state_policy"].update(changes)
        with pytest.raises(bundle.BootstrapError):
            bundle.validate_config(changed)


@pytest.mark.parametrize("extra", ["-----BEGIN PRIVATE KEY-----\naaaa\n-----END PRIVATE KEY-----",
                                   "not a certificate", "\x00"])
def test_public_ca_rejects_secret_material_and_junk(public_ca, extra):
    with pytest.raises(bundle.BootstrapError):
        bundle.validate_ca_pem(public_ca + extra)


def test_ca_count_and_byte_limits_fail_closed(public_ca):
    for value in (public_ca * 5, " " * 16385, "-----BEGIN CERTIFICATE-----\naaaa\n-----END CERTIFICATE-----"):
        with pytest.raises(bundle.BootstrapError):
            bundle.validate_ca_pem(value)


@pytest.mark.parametrize("whitespace", ["\n", "\r\n", " \n"])
def test_rendered_ca_always_works_in_actual_worker_tls_context(config, public_ca, whitespace, monkeypatch):
    from integration.client import controller_tls_context
    ca = public_ca.replace("-----BEGIN CERTIFICATE-----\n", "-----BEGIN CERTIFICATE-----" + whitespace)
    files = bundle.render_bundle(config, ca, REPOSITORY)
    env = json.loads(files["worker-runtime-environment.json"])
    assert set(env) == {"CONTROLLER_URL", "CONTROLLER_CA_PEM"}
    assert env["CONTROLLER_URL"] == "https://controller.agent-controller.internal:8443"
    monkeypatch.setenv("CONTROLLER_CA_PEM", env["CONTROLLER_CA_PEM"])
    context = controller_tls_context()
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    assert context.get_ca_certs()


def test_render_preserves_routes_guard_readiness_and_records_exact_bytes(config, public_ca):
    files = bundle.render_bundle(config, public_ca, REPOSITORY)
    nginx = files["controller-worker.nginx.conf"].decode()
    assert "listen 10.78.0.10:8443 ssl;" in nginx
    assert "~^POST:/stop$" not in nginx and "~^POST:/jobs$" not in nginx
    assert "proxy_next_upstream off;" in nginx
    controller = files["agent-controller.service"].decode()
    assert "wait-ready $MAINPID" in controller
    assert "PrivateDevices=no\nDevicePolicy=closed" in controller
    assert "ReadWritePaths=/srv/controller-volume /run/agent-controller" in controller
    assert "InaccessiblePaths=-/run/agent-controller-tls" in controller
    assert "[Install]\n" not in controller and "Restart=no" in controller
    assert "AF_NETLINK" in files["agent-controller-proxy.service"].decode()
    manifest = json.loads(files["bundle-manifest.json"])
    assert manifest["files"] == {name: bundle.sha256(data) for name, data in files.items()
                                 if name != "bundle-manifest.json"}
    source = json.loads(files["source-manifest.json"])
    assert len(source["packages"]) == 43
    assert source["source_sha256"]["controller/service.py"] == bundle.sha256(
        (REPOSITORY / "controller/service.py").read_bytes())


def test_bundle_write_is_private_and_never_overwrites(tmp_path):
    target = tmp_path / "bundle"
    bundle.write_bundle(target, {"file.json": b"safe\n"})
    assert target.stat().st_mode & 0o777 == 0o700
    assert (target / "file.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(bundle.BootstrapError, match="new_output_directory_required"):
        bundle.write_bundle(target, {"file.json": b"changed"})
    assert (target / "file.json").read_bytes() == b"safe\n"


def test_alias_inputs_and_duplicate_json_are_rejected(tmp_path):
    real = tmp_path / "real"
    real.write_bytes(b"safe")
    alias = tmp_path / "alias"
    alias.symlink_to(real)
    with pytest.raises(bundle.BootstrapError, match="input_alias"):
        bundle.regular_bytes(alias)
    with pytest.raises(bundle.BootstrapError, match="duplicate_json_key"):
        bundle.strict_json('{"mode":"synthetic","mode":"live"}')


@pytest.fixture
def empty_state(tmp_path):
    mount = tmp_path / "volume"
    mount.mkdir(mode=0o700)
    state = mount / "controller"
    state.mkdir(mode=0o700)
    policy = StatePolicy(mount, state, "vol-0123456789abcdef0",
                         "12345678-1234-1234-1234-123456789abc", os.geteuid(), os.getegid())
    info = mount.stat()
    observed = MountObservation(mount, "/dev/nvme1n1", policy.filesystem_uuid, policy.volume_id,
                                "ext4", "/", ("rw",), os.major(info.st_dev), os.minor(info.st_dev))
    return policy, lambda _mount: observed


def snapshot(directory):
    return {path.name: path.read_bytes() for path in directory.iterdir()}


def test_explicit_init_stops_zero_budget_seed_and_never_exposes_tokens(empty_state):
    policy, observe = empty_state
    result = initialize.initialize_synthetic(policy, observe=observe)
    assert result["seed_job_stopped"] and result["jobs"] == 1 and result["databases"] == 3
    assert result["rollback_protection"] == "external_recovery_proof_required"
    assert not result["project_budget_created"] and "token" not in json.dumps(result)
    with sqlite3.connect(policy.state_dir / "broker.sqlite") as database:
        assert database.execute("SELECT final_outcome,budget,live_enabled FROM jobs").fetchall() == [("stopped", 0, 0)]
        assert database.execute("SELECT count(*) FROM effects").fetchone() == (0,)
    assert all(path.stat().st_mode & 0o777 == 0o600 for path in policy.state_dir.iterdir())
    before = snapshot(policy.state_dir)
    with pytest.raises(bundle.BootstrapError, match="empty_state_directory_required"):
        initialize.initialize_synthetic(policy, observe=observe)
    assert snapshot(policy.state_dir) == before


def test_initial_schema_is_created_only_while_writer_lock_held(empty_state):
    policy, observe = empty_state
    class ProbeBroker(Broker):
        def _initialize(self):
            assert not self.db.exists()
            with (self.state_dir / ".broker.lock").open("r+b") as other:
                with pytest.raises(BlockingIOError):
                    fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            super()._initialize()
    initialize.initialize_synthetic(policy, observe=observe, broker_type=ProbeBroker)


def test_missing_mount_precedes_lock_creation_or_fallback(empty_state):
    policy, _observe = empty_state
    def absent(_path):
        raise StateGuardError("mount_metadata_unavailable")
    with pytest.raises(StateGuardError):
        initialize.initialize_synthetic(policy, observe=absent)
    assert list(policy.state_dir.iterdir()) == []


@pytest.mark.parametrize("stage", ["before_schema", "after_schema", "competing_file"])
def test_interrupted_or_racing_initialization_leaves_partial_state_and_refuses_retry(empty_state, stage):
    policy, observe = empty_state
    class FailingBroker(Broker):
        def __init__(self, *args, **kwargs):
            if stage == "before_schema":
                raise RuntimeError("simulated_crash")
            if stage == "competing_file":
                (policy.state_dir / "unexpected.sqlite").write_bytes(b"other-owner")
            super().__init__(*args, **kwargs)
        def create(self, _body):
            raise RuntimeError("simulated_crash")
    with pytest.raises((RuntimeError, bundle.BootstrapError)):
        initialize.initialize_synthetic(policy, observe=observe, broker_type=FailingBroker)
    before = snapshot(policy.state_dir)
    assert ".broker.lock" in before
    assert ("broker.sqlite" in before) == (stage == "after_schema")
    with pytest.raises(bundle.BootstrapError, match="empty_state_directory_required"):
        initialize.initialize_synthetic(policy, observe=observe)
    assert snapshot(policy.state_dir) == before


def test_activation_binds_source_and_absolute_two_hour_window():
    config, source = b"config", b"source"
    value = {"schema_version": 1, "mode": "synthetic", "bootstrap_sha256": bundle.sha256(config),
             "source_manifest_sha256": bundle.sha256(source), "not_before": 100, "expires_at": 200,
             "recovery_reference": "operator-review:synthetic-volume-1"}
    assert launch.verify_activation(value, config, source, now=150) == 200
    for change in ({"expires_at": 150}, {"expires_at": 10000}, {"not_before": 151},
                   {"source_manifest_sha256": "a" * 64}, {"mode": "live"}):
        with pytest.raises(bundle.BootstrapError):
            launch.verify_activation({**value, **change}, config, source, now=150)


def test_controller_mount_failure_prevents_credential_read(config, monkeypatch):
    import deploy.state_guard
    def blocked(_policy):
        raise StateGuardError("unexpected_state_mount")
    monkeypatch.setattr(deploy.state_guard, "verify_mount", blocked)
    monkeypatch.setattr(launch, "read_admin", lambda _config: pytest.fail("credential read before mount"))
    with pytest.raises(StateGuardError):
        launch.controller_preflight(config)


def test_synthetic_environment_omits_ambient_credentials_and_live_configuration(monkeypatch):
    for name in ("AWS_SECRET_ACCESS_KEY", "OPENAI_API_KEY", "CONTROLLER_LIVE_CONFIG", "HTTPS_PROXY"):
        monkeypatch.setenv(name, "must-not-propagate")
    result = launch.synthetic_environment("synthetic-admin-token")
    assert set(result) == {"PATH", "LANG", "PYTHONDONTWRITEBYTECODE", "PYTHONUNBUFFERED",
                           "OPENAI_AGENTS_DISABLE_TRACING", "CONTROLLER_ADMIN_TOKEN"}


def test_wait_ready_requires_exact_current_pid_and_loopback_origin(monkeypatch):
    monkeypatch.setattr(os, "kill", lambda _pid, _signal: None)
    monkeypatch.setattr(launch, "protected_file", lambda *_a, **_kw: b'{"pid":123,"url":"http://127.0.0.1:8787"}')
    launch.wait_ready(123)
    with pytest.raises(bundle.BootstrapError, match="readiness_mismatch"):
        launch.wait_ready(124)
    with pytest.raises(bundle.BootstrapError, match="readiness_timeout"):
        launch.wait_ready(123, timeout=0)
