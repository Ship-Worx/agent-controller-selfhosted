"""Render a new review bundle from exact local inputs; stdlib, no network/install."""
from __future__ import annotations

import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import stat


class BootstrapError(RuntimeError):
    """Bounded rejection code; never include credentials or file contents."""


APP = Path("/opt/agent-controller")
ETC = Path("/etc/agent-controller")
MOUNT = Path("/srv/controller-volume")
STATE = MOUNT / "controller"
CONTROLLER_USER = "agent-controller"
PROXY_USER = "agent-controller-proxy"
SOURCE_FILES = (
    "requirements.lock", "controller/__init__.py", "controller/engine.py",
    "controller/validators.py", "controller/durable.py", "controller/service.py",
    "controller/live_model.py", "controller/project_budget.py", "controller/installation.py",
    "workflows/__init__.py", "workflows/definitions.py",
    "integration/__init__.py", "integration/client.py", "integration/live_model.py",
    "integration/live_worker.py", "integration/worker.py", "integration/process.py",
    "deploy/state_guard.py", "deploy/self_host.py", "deploy/bootstrap/__init__.py",
    "deploy/bootstrap/bundle.py", "deploy/bootstrap/launch.py",
    "deploy/bootstrap/initialize.py", "deploy/controller-worker.nginx.conf",
    "deploy/bootstrap/controller.service", "deploy/bootstrap/proxy.service",
)
CONFIG_FIELDS = {
    "schema_version", "mode", "account", "region", "installation", "controller_private_ipv4",
    "controller_private_dns", "controller_uid", "controller_gid", "proxy_uid",
    "proxy_gid", "state_policy", "python_version", "nginx_version",
    "python_sha256", "nginx_sha256",
}
PEM_CERT = re.compile(r"-----BEGIN CERTIFICATE-----\s+[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----")


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def strict_json(data):
    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise BootstrapError("duplicate_json_key")
            value[key] = item
        return value
    def constant(_value):
        raise BootstrapError("invalid_json")
    try:
        value = json.loads(data, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, TypeError, UnicodeError):
        raise BootstrapError("invalid_json") from None
    if type(value) is not dict:
        raise BootstrapError("json_object_required")
    return value


def digest_string(value):
    return isinstance(value, str) and bool(re.fullmatch(r"[0-9a-f]{64}", value)) and value != "0" * 64


def validate_config(value, installation=None):
    from controller.installation import InstallationConfig
    from deploy.self_host import require_commercial_installation
    from deploy.state_guard import StatePolicy, StateGuardError
    if type(value) is not dict or set(value) != CONFIG_FIELDS:
        raise BootstrapError("exact_bootstrap_fields_required")
    try:
        installed = InstallationConfig.from_mapping(value["installation"])
        require_commercial_installation(installed)
        if installation is not None and installation != installed:
            raise ValueError
    except (TypeError, ValueError):
        raise BootstrapError("trusted_installation_mismatch") from None
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["mode"] != "synthetic" or value["account"] != installed.account_id
            or value["region"] != installed.region):
        raise BootstrapError("synthetic_target_required")
    try:
        ip = ipaddress.IPv4Address(value["controller_private_ipv4"])
        private = any(ip in ipaddress.ip_network(net) for net in
                      ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
    except (ValueError, TypeError):
        private = False
    if not private or str(ip) != value["controller_private_ipv4"]:
        raise BootstrapError("private_ipv4_required")
    hostname = value["controller_private_dns"]
    if (not isinstance(hostname, str) or len(hostname) > 253 or "." not in hostname
            or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                       for label in hostname.split("."))):
        raise BootstrapError("exact_private_dns_required")
    ids = [value[name] for name in ("controller_uid", "controller_gid", "proxy_uid", "proxy_gid")]
    if (any(type(item) is not int or not 1000 <= item <= 65533 for item in ids)
            or value["controller_uid"] == value["proxy_uid"]
            or value["controller_gid"] == value["proxy_gid"]):
        raise BootstrapError("separate_nonroot_identities_required")
    policy = value["state_policy"]
    if type(policy) is not dict or set(policy) != {"mountpoint", "state_dir", "volume_id", "filesystem_uuid", "uid", "gid"}:
        raise BootstrapError("exact_state_policy_required")
    try:
        StatePolicy(**policy)
    except (TypeError, StateGuardError):
        raise BootstrapError("invalid_state_policy") from None
    if (policy["mountpoint"] != str(MOUNT) or policy["state_dir"] != str(STATE)
            or policy["uid"] != value["controller_uid"] or policy["gid"] != value["controller_gid"]):
        raise BootstrapError("fixed_state_identity_required")
    if (value["python_version"] not in {"3.12.14", "3.12.15"}
            or not isinstance(value["nginx_version"], str)
            or not re.fullmatch(r"1\.[0-9]{1,2}\.[0-9]{1,2}", value["nginx_version"])
            or not all(digest_string(value[name]) for name in ("python_sha256", "nginx_sha256"))):
        raise BootstrapError("exact_runtime_pins_required")
    return value


def validate_ca_pem(value):
    if not isinstance(value, str) or not 1 <= len(value.encode()) <= 16384:
        raise BootstrapError("bounded_public_ca_required")
    certificates = PEM_CERT.findall(value)
    if not certificates or len(certificates) > 4 or PEM_CERT.sub("", value).strip():
        raise BootstrapError("certificate_only_ca_required")
    try:
        normalized = "".join(ssl.DER_cert_to_PEM_cert(base64.b64decode(
            "".join(cert.removeprefix("-----BEGIN CERTIFICATE-----")
                    .removesuffix("-----END CERTIFICATE-----").split()), validate=True))
            for cert in certificates)
        if len(normalized.encode()) > 16384:
            raise BootstrapError("bounded_public_ca_required")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.load_verify_locations(cadata=normalized)
        if not context.get_ca_certs():
            raise BootstrapError("ca_certificate_required")
    except (ValueError, ssl.SSLError):
        raise BootstrapError("invalid_public_ca") from None
    return normalized


def regular_bytes(path, *, limit=2_000_000):
    """Reject symlink components and bounded nonregular/hardlinked inputs."""
    path = Path(path)
    try:
        if any(part.is_symlink() for part in (path, *path.parents)):
            raise BootstrapError("input_alias_rejected")
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > limit:
                raise BootstrapError("bounded_regular_file_required")
            data = handle.read(limit + 1)
            if len(data) > limit:
                raise BootstrapError("bounded_regular_file_required")
            return data
    except OSError:
        raise BootstrapError("required_input_unavailable") from None


def locked_versions(lock):
    versions = {}
    for line in lock.decode().splitlines():
        if not line or line.startswith(("#", " ")):
            continue
        match = re.fullmatch(r"([a-z0-9-]+)==([a-zA-Z0-9.+]+) \\", line)
        if not match or match[1] in versions:
            raise BootstrapError("reviewed_dependency_lock_required")
        versions[match[1]] = match[2]
    if not versions or versions.get("openai-agents") != "0.23.1" or versions.get("openai") != "3.29.0":
        raise BootstrapError("reviewed_dependency_lock_required")
    return versions


def render_bundle(config, ca_pem, source_root, *, installation=None):
    config = validate_config(config, installation)
    ca_pem = validate_ca_pem(ca_pem)
    sources = {name: regular_bytes(Path(source_root) / name) for name in SOURCE_FILES}
    nginx = sources["deploy/controller-worker.nginx.conf"].decode()
    substitutions = {
        "__REVIEWED_CONTROLLER_PRIVATE_IPV4__": config["controller_private_ipv4"],
        "__REVIEWED_CONTROLLER_PRIVATE_DNS__": config["controller_private_dns"],
    }
    if any(token not in nginx for token in substitutions):
        raise BootstrapError("nginx_template_contract_changed")
    for token, replacement in substitutions.items():
        nginx = nginx.replace(token, replacement)
    if re.search(r"__REVIEWED_[A-Z0-9_]+__", nginx):
        raise BootstrapError("unresolved_nginx_input")
    files = {
        "bootstrap.json": canonical(config),
        "state-policy.json": canonical(config["state_policy"]),
        "worker-runtime-environment.json": canonical({
            "CONTROLLER_URL": "https://" + config["controller_private_dns"] + ":8443",
            "CONTROLLER_CA_PEM": ca_pem,
        }),
        "controller-ca.pem": ca_pem.encode(),
        "controller-worker.nginx.conf": nginx.encode(),
        "agent-controller.service": sources["deploy/bootstrap/controller.service"],
        "agent-controller-proxy.service": sources["deploy/bootstrap/proxy.service"],
        "source-manifest.json": canonical({"schema_version": 1,
            "source_sha256": {name: sha256(data) for name, data in sources.items()},
            "packages": locked_versions(sources["requirements.lock"])}),
    }
    files["bundle-manifest.json"] = canonical({"schema_version": 1,
        "files": {name: sha256(data) for name, data in files.items()}})
    return files


def write_bundle(destination, files):
    destination = Path(destination)
    if any(path.is_symlink() for path in (destination, *destination.parents)):
        raise BootstrapError("output_alias_rejected")
    if any(Path(name).name != name for name in files):
        raise BootstrapError("flat_bundle_required")
    try:
        destination.mkdir(mode=0o700)
        for name, data in files.items():
            fd = os.open(destination / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
    except OSError:
        raise BootstrapError("new_output_directory_required") from None


def main():
    from controller.installation import load_installation
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--installation", required=True, help="absolute trusted operator installation JSON")
    parser.add_argument("--public-ca", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    try:
        files = render_bundle(strict_json(regular_bytes(args.config, limit=16384)),
                              regular_bytes(args.public_ca, limit=16384).decode(), args.source_root,
                              installation=load_installation(Path(args.installation)))
        write_bundle(args.output, files)
        print(json.dumps({"status": "review_bundle_written", "files": len(files),
                          "bundle_manifest_sha256": sha256(files["bundle-manifest.json"]),
                          "installed": False, "release_ready": False}))
        return 0
    except (BootstrapError, UnicodeError, ValueError, OSError) as exc:
        print(json.dumps({"status": "blocked", "reason": str(exc) if isinstance(exc, BootstrapError) else "invalid_text"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
