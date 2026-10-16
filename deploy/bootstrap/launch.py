"""Installed-host preflight and explicit synthetic service startup; no provisioning."""
from __future__ import annotations

import argparse
import grp
from importlib import metadata
import json
import math
import os
from pathlib import Path
import platform
import pwd
import re
import signal
import ssl
import stat
import subprocess
import sys
import time

# The installed unit uses Python -I and this absolute trusted script, not PYTHONPATH.
if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from deploy.bootstrap.bundle import (APP, ETC, STATE, SOURCE_FILES, BootstrapError,
    canonical, locked_versions, regular_bytes, sha256, strict_json, validate_config,
    validate_ca_pem)


def protected_file(path, *, uid=0, mode=None, limit=2_000_000):
    """Require protected real ancestry and a regular single-link bounded file."""
    path = Path(path)
    try:
        for parent in path.parents:
            info = parent.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in {0, uid}
                    or stat.S_IMODE(info.st_mode) & 0o022):
                raise BootstrapError("unprotected_file_ancestry")
        info = path.lstat()
        if info.st_uid != uid or stat.S_IMODE(info.st_mode) & 0o022:
            raise BootstrapError("unprotected_file")
        if mode is not None and stat.S_IMODE(info.st_mode) != mode:
            raise BootstrapError("unsafe_file_mode")
        return regular_bytes(path, limit=limit)
    except OSError:
        raise BootstrapError("required_protected_file_missing") from None


def runtime_directory(path, uid, gid):
    try:
        info = Path(path).lstat()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
                or (info.st_uid, info.st_gid) != (uid, gid)):
            raise BootstrapError("unsafe_runtime_directory")
    except OSError:
        raise BootstrapError("runtime_directory_missing") from None


def verify_activation(value, config_bytes, source_bytes, *, now=None):
    fields = {"schema_version", "mode", "bootstrap_sha256", "source_manifest_sha256",
              "not_before", "expires_at", "recovery_reference"}
    now = time.time() if now is None else now
    if type(value) is not dict or set(value) != fields:
        raise BootstrapError("exact_activation_required")
    start, end = value["not_before"], value["expires_at"]
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["mode"] != "synthetic"
            or value["bootstrap_sha256"] != sha256(config_bytes)
            or value["source_manifest_sha256"] != sha256(source_bytes)
            or type(start) is not int or type(end) is not int
            or not start <= now < end or not 0 < end - start <= 7200
            or not isinstance(value["recovery_reference"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}", value["recovery_reference"])):
        raise BootstrapError("activation_invalid_or_expired")
    return end


def verify_installed(role):
    if role not in {"controller", "proxy"} or Path(__file__).resolve().parents[2] != APP:
        raise BootstrapError("reviewed_installed_location_required")
    files = {name: protected_file(ETC / name) for name in (
        "bootstrap.json", "state-policy.json", "worker-runtime-environment.json",
        "controller-ca.pem", "controller-worker.nginx.conf", "agent-controller.service",
        "agent-controller-proxy.service", "source-manifest.json")}
    manifest = strict_json(protected_file(ETC / "bundle-manifest.json"))
    if manifest != {"schema_version": 1, "files": {name: sha256(data) for name, data in files.items()}}:
        raise BootstrapError("installed_bundle_mismatch")
    config = validate_config(strict_json(files["bootstrap.json"]))
    if files["state-policy.json"] != canonical(config["state_policy"]):
        raise BootstrapError("installed_policy_mismatch")
    source = strict_json(files["source-manifest.json"])
    sources = {name: protected_file(APP / name) for name in SOURCE_FILES}
    if source != {"schema_version": 1,
                  "source_sha256": {name: sha256(data) for name, data in sources.items()},
                  "packages": locked_versions(sources["requirements.lock"])}:
        raise BootstrapError("installed_source_mismatch")
    for unit in ("agent-controller.service", "agent-controller-proxy.service"):
        if protected_file(Path("/etc/systemd/system") / unit) != files[unit]:
            raise BootstrapError("installed_unit_mismatch")
    prefix = "controller" if role == "controller" else "proxy"
    name = "agent-controller" if role == "controller" else "agent-controller-proxy"
    uid, gid = config[prefix + "_uid"], config[prefix + "_gid"]
    try:
        if ((pwd.getpwnam(name).pw_uid, grp.getgrnam(name).gr_gid) != (uid, gid)
                or (os.geteuid(), os.getegid()) != (uid, gid)
                or set(os.getgroups()) - {gid}):
            raise BootstrapError("service_identity_mismatch")
    except KeyError:
        raise BootstrapError("service_identity_missing") from None
    if platform.python_version() != config["python_version"]:
        raise BootstrapError("python_version_mismatch")
    if sha256(protected_file(APP / ".venv/bin/python", limit=100_000_000)) != config["python_sha256"]:
        raise BootstrapError("python_binary_mismatch")
    try:
        if any(metadata.version(name) != version for name, version in source["packages"].items()):
            raise BootstrapError("runtime_packages_mismatch")
    except metadata.PackageNotFoundError:
        raise BootstrapError("runtime_packages_missing") from None
    ca = validate_ca_pem(files["controller-ca.pem"].decode())
    if strict_json(files["worker-runtime-environment.json"]) != {
            "CONTROLLER_URL": "https://" + config["controller_private_dns"] + ":8443",
            "CONTROLLER_CA_PEM": ca}:
        raise BootstrapError("worker_environment_mismatch")
    expiry = verify_activation(strict_json(protected_file(ETC / "activation.json")),
                               files["bootstrap.json"], files["source-manifest.json"])
    return config, ca, expiry


def synthetic_environment(admin_token=None):
    env = {"PATH": "/usr/sbin:/usr/bin:/bin", "LANG": "C.UTF-8",
           "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
           "OPENAI_AGENTS_DISABLE_TRACING": "1"}
    if admin_token is not None:
        env["CONTROLLER_ADMIN_TOKEN"] = admin_token
    return env


def read_admin(config):
    token = protected_file("/run/agent-controller-secrets/admin-token",
                           uid=config["controller_uid"], mode=0o600, limit=512).decode("ascii")
    if not re.fullmatch(r"[A-Za-z0-9_-]{24,512}", token):
        raise BootstrapError("admin_credential_invalid")
    return token


def controller_preflight(config):
    from deploy.state_guard import StatePolicy, verify_mount
    # No Broker or directory creation occurs before the exact mount check.
    verify_mount(StatePolicy(**config["state_policy"]))
    runtime_directory("/run/agent-controller", config["controller_uid"], config["controller_gid"])
    if Path("/run/agent-controller/ready.json").exists():
        raise BootstrapError("stale_readiness_file")
    return read_admin(config)


def tls_memory_check(ca, hostname, certificate, private_key):
    """Validate key/chain/hostname/expiry through in-memory TLS; no socket."""
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.minimum_version = ssl.TLSVersion.TLSv1_2
    server_context.load_cert_chain(certificate, private_key)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.minimum_version = ssl.TLSVersion.TLSv1_2
    client_context.load_verify_locations(cadata=ca)
    ci, co, si, so = (ssl.MemoryBIO() for _ in range(4))
    client = client_context.wrap_bio(ci, co, server_hostname=hostname)
    server = server_context.wrap_bio(si, so, server_side=True)
    complete = set()
    for _ in range(20):
        for name, peer in (("client", client), ("server", server)):
            if name not in complete:
                try:
                    peer.do_handshake()
                    complete.add(name)
                except ssl.SSLWantReadError:
                    pass
        if complete == {"client", "server"}:
            return
        si.write(co.read())
        ci.write(so.read())
    raise BootstrapError("tls_handshake_incomplete")


def proxy_preflight(config, ca, *, runner=subprocess.run):
    uid, gid = config["proxy_uid"], config["proxy_gid"]
    runtime_directory("/run/agent-controller-proxy", uid, gid)
    runtime_directory("/run/agent-controller-tls", uid, gid)
    certificate, key = "/run/agent-controller-tls/server.crt", "/run/agent-controller-tls/server.key"
    protected_file(certificate, uid=uid, mode=0o600, limit=65536)
    protected_file(key, uid=uid, mode=0o600, limit=16384)
    tls_memory_check(ca, config["controller_private_dns"], certificate, key)
    if sha256(protected_file("/usr/sbin/nginx", limit=100_000_000)) != config["nginx_sha256"]:
        raise BootstrapError("nginx_binary_mismatch")
    result = runner(["/usr/sbin/nginx", "-v"], capture_output=True, text=True, timeout=5, check=False)
    if result.returncode or result.stderr.strip() != "nginx version: nginx/" + config["nginx_version"]:
        raise BootstrapError("nginx_version_mismatch")
    result = runner(["/usr/sbin/ip", "-json", "-4", "address", "show"],
                    capture_output=True, text=True, timeout=5, check=False)
    if result.returncode or len(result.stdout) > 65536:
        raise BootstrapError("assigned_private_ip_unavailable")
    addresses = {item.get("local") for link in json.loads(result.stdout)
                 for item in link.get("addr_info", []) if item.get("family") == "inet"}
    if config["controller_private_ipv4"] not in addresses:
        raise BootstrapError("private_ip_not_assigned")
    for directory in ("client-body", "proxy"):
        path = Path("/run/agent-controller-proxy") / directory
        path.mkdir(mode=0o700, exist_ok=True)
        runtime_directory(path, uid, gid)
    result = runner(["/usr/sbin/nginx", "-t", "-c", str(ETC / "controller-worker.nginx.conf")],
                    capture_output=True, text=True, timeout=10, check=False)
    if result.returncode:
        raise BootstrapError("nginx_configuration_rejected")


def wait_ready(pid, *, timeout=30):
    if type(pid) is not int or pid <= 1:
        raise BootstrapError("controller_pid_required")
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        os.kill(pid, 0)
        try:
            value = strict_json(protected_file("/run/agent-controller/ready.json", uid=os.geteuid(), mode=0o600))
        except BootstrapError:
            time.sleep(.05)
            continue
        if value == {"url": "http://127.0.0.1:8787", "pid": pid}:
            return
        raise BootstrapError("controller_readiness_mismatch")
    raise BootstrapError("controller_readiness_timeout")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("controller", "proxy", "wait-ready"))
    parser.add_argument("pid", nargs="?", type=int)
    args = parser.parse_args()
    try:
        if args.action == "wait-ready":
            wait_ready(args.pid)
            return 0
        config, ca, expiry = verify_installed(args.action)
        os.environ.clear()
        os.environ.update(synthetic_environment())
        if args.action == "controller":
            token = controller_preflight(config)
            os.environ.update(synthetic_environment(token))
            # Absolute approved activation expiry, even after a late restart.
            remaining = math.floor(expiry - time.time())
            if remaining <= 0:
                raise BootstrapError("activation_invalid_or_expired")
            signal.signal(signal.SIGALRM, signal.SIG_DFL)
            signal.alarm(remaining)
            from controller import service
            sys.argv = ["controller.service", "--state-dir", str(STATE), "--port", "8787",
                        "--ready-file", "/run/agent-controller/ready.json",
                        "--state-policy", str(ETC / "state-policy.json")]
            service.main()
        else:
            proxy_preflight(config, ca)
            os.execve("/usr/sbin/nginx", ["nginx", "-c", str(ETC / "controller-worker.nginx.conf"),
                                        "-g", "daemon off;"], synthetic_environment())
        return 0
    except Exception:
        # Never relay Nginx/SSL/credential/parser exceptions into service logs.
        print('{"status":"blocked","reason":"bootstrap_preflight_failed"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
