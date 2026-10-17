"""Preview sanitized agent/controller records; upload only with explicit --send.

This operator-side, post-run adapter has no agent or controller runtime hooks.
The original private report is the retry source; no action is ever retried here.
"""
from __future__ import annotations

import argparse
import json
import math
import multiprocessing
import os
from pathlib import Path
import ssl
import stat
import sys
from urllib.error import HTTPError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from .trace_export import ExportError, build_export


MAX_REPORT_BYTES = 262_144
MAX_ACK_BYTES = 65_536
SOCKET_TIMEOUT_SECONDS = 5
DELIVERY_TIMEOUT_SECONDS = 15
API_ORIGIN = "https://api.braintrust.dev"


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ExportError("duplicate_json_key")
        result[key] = value
    return result


def _nonfinite(_value):
    raise ExportError("nonfinite_json_number")


def _json(raw):
    try:
        value = json.loads(raw, object_pairs_hook=_object, parse_constant=_nonfinite)
        # Unknown fields are never exported, but still must have bounded depth.
        pending = [(value, 0)]
        while pending:
            item, depth = pending.pop()
            if depth > 32:
                raise ExportError("json_depth_limit")
            if type(item) is dict:
                pending.extend((child, depth + 1) for child in item.values())
            elif type(item) is list:
                pending.extend((child, depth + 1) for child in item)
            elif type(item) is float:
                if not math.isfinite(item):
                    raise ExportError("nonfinite_json_number")
        return value
    except (ValueError, TypeError, RecursionError, UnicodeError):
        raise ExportError("invalid_json") from None


def load_report(path: Path):
    """Read one bounded regular file, never a pipe, device or leaf symlink."""
    descriptor = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_REPORT_BYTES):
            raise ExportError("invalid_report_file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            raw = stream.read(MAX_REPORT_BYTES + 1)
        if not 0 < len(raw) <= MAX_REPORT_BYTES:
            raise ExportError("report_size_limit")
        value = _json(raw.decode("utf-8"))
        if type(value) is not dict:
            raise ExportError("report_object_required")
        return value
    except (OSError, UnicodeError):
        raise ExportError("invalid_report_file") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def write_preview(path: Path, data: bytes):
    """Create a private preview without replacing any existing filesystem entry."""
    descriptor = None
    created = False
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        if created:
            path.unlink(missing_ok=True)
        raise ExportError("preview_write_failed") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def _result(status, reason, *, http_status=None, delivery_unknown=False):
    result = {"status": status, "reason": reason, "attempts": 1,
              "delivery_unknown": delivery_unknown}
    if http_status is not None:
        result["http_status"] = http_status
    return result


def _post_events(payload: bytes, project_id: str, api_key: str, *, opener=None):
    """One HTTPS request; return fixed codes, never error text or response data.

    The caller runs this in a killable process to bound the complete operation,
    including DNS, connection, response headers and a slow response body.
    """
    try:
        expected_ids = [row["id"] for row in json.loads(payload)["events"]]
        if opener is None:
            # Honor the trusted operator's proxy/CA setup. Redirects can never
            # forward the credential, and TLS certificate verification stays on.
            opener = build_opener(HTTPSHandler(context=ssl.create_default_context()), NoRedirect())
        request = Request(API_ORIGIN + "/v1/project_logs/" + project_id + "/insert",
                          data=payload, method="POST",
                          headers={"Authorization": "Bearer " + api_key,
                                   "Content-Type": "application/json",
                                   "Accept": "application/json"})
        with opener.open(request, timeout=SOCKET_TIMEOUT_SECONDS) as response:
            code = response.status
            if code != 200:
                return _result("unknown", "unexpected_http_status", http_status=code,
                               delivery_unknown=True)
            raw = response.read(MAX_ACK_BYTES + 1)
        if len(raw) > MAX_ACK_BYTES:
            return _result("unknown", "acknowledgement_invalid", http_status=200,
                           delivery_unknown=True)
        try:
            ack = _json(raw.decode("utf-8"))
        except (ExportError, UnicodeError):
            ack = None
        if (type(ack) is not dict or set(ack) != {"row_ids"}
                or type(ack["row_ids"]) is not list or ack["row_ids"] != expected_ids):
            return _result("unknown", "acknowledgement_invalid", http_status=200,
                           delivery_unknown=True)
        return _result("sent", "acknowledged", http_status=200)
    except HTTPError as error:
        code = error.code
        error.close()  # Deliberately do not read or log the error response body.
        unknown = code >= 500 or code == 408
        return _result("unknown" if unknown else "rejected", "http_rejected",
                       http_status=code, delivery_unknown=unknown)
    except Exception:
        # Failures after sending may already have committed rows remotely.
        return _result("unknown", "transport_failed", delivery_unknown=True)


def _send_child(connection, payload, project_id, api_key):
    try:
        connection.send(_post_events(payload, project_id, api_key))
    except BaseException:
        pass
    finally:
        connection.close()


def _deliver(payload, project_id, api_key):
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_send_child, args=(sender, payload, project_id, api_key))
    started = False
    try:
        process.start()
        started = True
        sender.close()
        if not receiver.poll(DELIVERY_TIMEOUT_SECONDS):
            return _result("unknown", "delivery_deadline_exceeded", delivery_unknown=True)
        try:
            result = receiver.recv()
        except (EOFError, OSError):
            return _result("unknown", "exporter_unavailable", delivery_unknown=True)
        return result
    except Exception:
        return _result("unknown", "exporter_unavailable", delivery_unknown=True)
    finally:
        sender.close()
        receiver.close()
        if started:
            if process.is_alive():
                process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join()
        process.close()


def send_report(report, project_id, api_key):
    """Rebuild a sanitized batch before any network work; never send raw reports."""
    export = build_export(report, project_id)
    if not export["events"]:
        raise ExportError("no_exportable_events")
    if (type(api_key) is not str or not 16 <= len(api_key) <= 4096
            or any(not 33 <= ord(char) <= 126 for char in api_key)):
        raise ExportError("braintrust_credential_required")
    payload = json.dumps({"events": export["events"]}, separators=(",", ":"),
                         allow_nan=False).encode()
    result = _deliver(payload, export["project_id"], api_key)
    return {**result, "row_count": len(export["events"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--project-id", required=True)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--send", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = load_report(args.report)
        export = build_export(report, args.project_id)
        preview = (json.dumps(export, indent=2, allow_nan=False) + "\n").encode()
        if args.output is not None:
            write_preview(args.output, preview)
        if args.send:
            result = send_report(report, args.project_id, os.environ.get("BRAINTRUST_API_KEY"))
            print(json.dumps(result, allow_nan=False))
            return 0 if result["status"] == "sent" else 1
        if args.output is None:
            print(preview.decode("utf-8"), end="")
        else:
            print(json.dumps({"status": "dry_run", "network_enabled": False,
                              "preview_written": True, "row_count": len(export["events"]),
                              "evaluations": export["evaluations"]}, allow_nan=False))
        return 0
    except (ExportError, OSError, ValueError, TypeError, RecursionError):
        # Never echo paths, input values, credentials, response bodies or errors.
        print(json.dumps({"status": "not_sent", "reason": "export_rejected"}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
