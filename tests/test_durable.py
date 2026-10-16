"""Independent SQLite authority regressions with fictional prices and identities.

These tests use separate authority handles/processes and inspect an independent
list of dispatched effects. They do not establish OS identity, database access
isolation, real provider prices, or safe restoration of both authority files.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
import multiprocessing
from pathlib import Path
import shutil
import sqlite3
import tempfile
import threading
import unittest

from controller.durable import DurableAuthority, DurableError
from controller.engine import Attempt, Binding, Capability, Contract, Limits, ValidationOutcome
from tests.validator_support import synthetic_validator


READ = Capability("inspect", "source.read", "record-a", "reader")
RELEASE = Capability("release", "report.release", "report-a", "sink")
CONTEXT = {"record": "record-a", "task": "Summarize this fictional record."}
PRICES = {"source.read": 7, "report.release": 11}


def fixed_now():
    return 100.0


def contract():
    """The test's answer key declares inspect before release, independently."""
    return Contract(
        workflow_id="durable-two-step", version="test-1",
        purpose="Inspect one fictional record and release its supported report.",
        capabilities=frozenset((READ, RELEASE)),
        required_context={"inspect": ("record",), "release": ("record", "task")},
        step_dependencies={"inspect": (), "release": ("inspect",)},
        limits=Limits(budget_calls=8, runtime_seconds=60, max_children=4, max_depth=3),
        allowed_principals=frozenset((("tenant-a", "operator-a"),)),
        payload_fields={"source.read": ("id",), "report.release": ("id", "value")},
        delegable_context_fields=frozenset(("record", "task")),
    )


def read(operation="read-1"):
    return Attempt(operation, "inspect", "source.read", "record-a", "reader", {"id": "record-a"})


def release(operation="release-1"):
    return Attempt(operation, "release", "report.release", "report-a", "sink",
                   {"id": "record-a", "value": "fictional supported report"})


def reserve_process(path, epoch, token, operation, ready, start, answers):
    """A separate SQLite connection/process contending for the final seven units."""
    authority = DurableAuthority(path, contract(), synthetic_validator(contract()), prices=PRICES, budget_microusd=7,
                                 clock=fixed_now, epoch=epoch)
    ready.put(operation)
    if not start.wait(5):
        raise RuntimeError("test barrier timed out")
    result = authority.reserve(token, read(operation))
    for _ in range(3):
        if result.reason != "authority_changed_retry":
            break
        result = authority.reserve(token, read(operation))
    answers.put((result.status, result.reason, result.ticket))


class DurableTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "authority.sqlite"
        self.binding = Binding("tenant-a", "operator-a", "session-a", "worker-a")
        self.effects = []
        self.authority = self.make_authority()
        self.token = self.authority.admit(self.binding, CONTEXT)

    def make_authority(self, *, path=None, selected=None, validator=None, budget=100, prices=None):
        selected = selected or contract()
        return DurableAuthority(path or self.path, selected, synthetic_validator(selected, validator),
                                prices=PRICES if prices is None else prices,
                                budget_microusd=budget, clock=fixed_now).activate()

    def child(self, token=None, capabilities=frozenset((READ, RELEASE))):
        return self.authority.delegate(
            token or self.token, replace(self.binding, session="child-session", worker="child"),
            capabilities, CONTEXT)

    def observe_claim(self, ticket, recipients=frozenset(("reader", "sink"))):
        claimed = self.authority.claim(ticket, allowed_recipients=recipients)
        if claimed.dispatch is not None:
            request = claimed.dispatch.attempt
            self.effects.append((request.operation_id, request.action, request.resource,
                                 request.recipient, dict(request.payload)))
        return claimed

    def complete(self, attempt=None, *, cost=5):
        attempt = attempt or read()
        reserved = self.authority.reserve(self.token, attempt)
        self.assertEqual(reserved.status, "reserved", reserved)
        claimed = self.observe_claim(reserved.ticket)
        self.assertEqual(claimed.status, "allowed", claimed)
        result = self.authority.settle(reserved.ticket, {"observed": attempt.operation_id}, cost)
        self.assertEqual(result.status, "allowed", result)
        return reserved.ticket

    def assert_no_authorized_dispatch(self):
        self.assertEqual(self.effects, [])
        with sqlite3.connect(self.path) as connection:
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM audit WHERE event='dispatch_authorized'").fetchone()[0], 0)

    def test_allowed_ordered_workflow_observes_exact_effects_and_actual_money(self):
        self.complete(read(), cost=5)
        self.complete(release(), cost=9)
        self.assertEqual(self.effects, [
            ("read-1", "source.read", "record-a", "reader", {"id": "record-a"}),
            ("release-1", "report.release", "report-a", "sink",
             {"id": "record-a", "value": "fictional supported report"}),
        ])
        snapshot = self.authority.snapshot(self.token)
        self.assertEqual((snapshot.calls_used, snapshot.reserved_microusd,
                          snapshot.settled_microusd, snapshot.exposure_microusd), (2, 0, 14, 14))

    def test_prices_and_budget_must_be_nonnegative_integer_microusd(self):
        for value in (-1, 0.1, True, "7"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    DurableAuthority(self.path, contract(), prices=PRICES, budget_microusd=value)
                with self.assertRaises(ValueError):
                    DurableAuthority(self.path, contract(), prices={**PRICES, "source.read": value},
                                     budget_microusd=100)
        with self.assertRaises(ValueError):
            DurableAuthority(self.path, contract(), prices={"source.read": 7}, budget_microusd=100)

    def test_two_processes_cannot_both_reserve_last_monetary_allowance(self):
        path = Path(self.temp.name) / "race.sqlite"
        authority = self.make_authority(path=path, budget=7)
        token = authority.admit(self.binding, CONTEXT)
        context = multiprocessing.get_context("spawn")
        ready, answers, start = context.Queue(), context.Queue(), context.Event()
        processes = [context.Process(target=reserve_process,
                     args=(str(path), authority.epoch, token, f"race-{i}", ready, start, answers))
                     for i in range(2)]
        try:
            for process in processes:
                process.start()
            self.assertEqual({ready.get(timeout=5) for _ in processes}, {"race-0", "race-1"})
            start.set()
            results = [answers.get(timeout=5) for _ in processes]
            self.assertEqual(sorted((r[0], r[1]) for r in results),
                             [("held", "budget_exhausted"), ("reserved", "reserved")])
            snapshot = authority.snapshot(token)
            self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (1, 7))
        finally:
            start.set()
            for process in processes:
                if process.pid is not None:
                    process.join(5)
                    if process.is_alive():
                        process.terminate()
                        process.join(5)
                    self.assertEqual(process.exitcode, 0)
            ready.close()
            answers.close()

    def test_reservation_survives_reopen_and_duplicate_reserve_costs_nothing(self):
        reserved = self.authority.reserve(self.token, read())
        restarted = self.authority.reopen()
        replay = restarted.reserve(self.token, read())
        self.assertEqual((replay.status, replay.ticket, replay.replayed),
                         ("reserved", reserved.ticket, True))
        snapshot = restarted.snapshot(self.token)
        self.assertEqual((snapshot.calls_used, snapshot.reserved_microusd), (1, 7))
        self.assertEqual(restarted.claim(reserved.ticket).status, "allowed")

    def test_settled_replay_keeps_receipt_call_count_and_cost(self):
        ticket = self.complete(cost=5)
        replay = self.authority.reopen().reserve(self.token, read())
        self.assertEqual((replay.status, replay.replayed, replay.ticket), ("allowed", True, ticket))
        self.assertEqual(dict(replay.receipt), {"observed": "read-1"})
        self.assertEqual(len(self.effects), 1)
        snapshot = self.authority.snapshot(self.token)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (1, 5))

    def test_dispatched_lost_reply_stays_reserved_and_blocks_new_work_after_restart(self):
        reserved = self.authority.reserve(self.token, read())
        self.assertEqual(self.observe_claim(reserved.ticket).status, "allowed")
        restarted = self.authority.reopen()
        snapshot = restarted.snapshot(self.token)
        self.assertEqual((snapshot.reserved_microusd, snapshot.unknown_operations), (7, ("read-1",)))
        self.assertEqual(restarted.reserve(self.token, read("next")).reason, "operation_unknown")
        self.assertEqual(restarted.claim(reserved.ticket).reason, "already_claimed")
        restarted.mark_unknown(reserved.ticket)
        snapshot = restarted.reopen().snapshot(self.token)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (1, 7))
        self.assertEqual(len(self.effects), 1)

    def test_unknown_outcome_blocks_previously_reserved_second_claim(self):
        first = self.authority.reserve(self.token, read("first"))
        second = self.authority.reserve(self.token, read("second"))
        self.assertEqual((first.status, second.status), ("reserved", "reserved"))
        self.assertEqual(self.observe_claim(first.ticket).status, "allowed")
        self.authority.mark_unknown(first.ticket)
        held = self.observe_claim(second.ticket)
        self.assertEqual((held.status, held.reason, held.dispatch),
                         ("held", "operation_unknown", None))
        snapshot = self.authority.reopen().snapshot(self.token)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd,
                          snapshot.unknown_operations), (2, 14, ("first",)))
        self.assertEqual([effect[0] for effect in self.effects], ["first"])

    def test_old_controller_and_unclaimed_ticket_fenced_by_new_epoch(self):
        reserved = self.authority.reserve(self.token, read())
        replacement = self.authority.reopen().activate()
        self.assertEqual(self.authority.reserve(self.token, read("stale")).reason, "controller_fenced")
        self.assertEqual(self.authority.claim(reserved.ticket).reason, "controller_fenced")
        self.assertEqual(replacement.claim(reserved.ticket).reason, "ticket_fenced")
        self.assertEqual(replacement.snapshot(self.token).reserved_microusd, 7)
        self.assert_no_authorized_dispatch()

    def test_authority_only_stale_restore_quarantines_against_independent_anchor(self):
        stale = Path(self.temp.name) / "stale.sqlite"
        shutil.copyfile(self.path, stale)
        self.authority.reserve(self.token, read())
        shutil.copyfile(stale, self.path)
        with self.assertRaisesRegex(DurableError, "restore_quarantined"):
            self.authority.reopen()
        self.assertEqual(self.authority.reserve(self.token, read("after-restore")).reason,
                         "restore_quarantined")
        self.assert_no_authorized_dispatch()

    def test_missing_fence_is_not_recreated_as_fresh_authority(self):
        Path(self.authority.fence_path).unlink()
        with self.assertRaisesRegex(DurableError, "restore_anchor_missing"):
            self.authority.reopen()
        self.assertFalse(Path(self.authority.fence_path).exists())
        self.assert_no_authorized_dispatch()

    def test_settlement_callback_replay_is_idempotent_and_changed_receipt_stops(self):
        ticket = self.complete()
        repeat = self.authority.settle(ticket, {"observed": "read-1"}, 5)
        self.assertEqual((repeat.status, repeat.reason, repeat.replayed),
                         ("allowed", "settlement_replay", True))
        conflict = self.authority.settle(ticket, {"observed": "other-effect"}, 5)
        self.assertEqual((conflict.status, conflict.reason), ("denied", "settlement_conflict"))
        snapshot = self.authority.snapshot(self.token)
        self.assertTrue(snapshot.stopped)
        self.assertEqual(snapshot.settled_microusd, 5)
        self.assertEqual(len(self.effects), 1)

    def test_invalid_settlement_keeps_reservation_and_overrun_records_observed_cost(self):
        for actual in (8, -1, True, 0.5):
            with self.subTest(actual=actual):
                authority = self.make_authority(path=Path(self.temp.name) / f"overrun-{actual}.sqlite")
                token = authority.admit(self.binding, CONTEXT)
                reserved = authority.reserve(token, read())
                authority.claim(reserved.ticket)
                result = authority.settle(reserved.ticket, {"receipt": "synthetic"}, actual)
                reason = "settlement_overrun" if actual == 8 else "settlement_invalid"
                self.assertEqual((result.status, result.reason), ("denied", reason))
                snapshot = authority.snapshot(token)
                self.assertTrue(snapshot.stopped)
                if actual == 8:
                    # A detected price failure must truthfully retain actual exposure.
                    self.assertEqual((snapshot.reserved_microusd, snapshot.settled_microusd), (0, 8))
                    repeat = authority.settle(reserved.ticket, {"receipt": "synthetic"}, 8)
                    self.assertEqual((repeat.reason, repeat.replayed), ("settlement_overrun", True))
                    self.assertEqual(authority.snapshot(token).exposure_microusd, 8)
                else:
                    self.assertEqual((snapshot.reserved_microusd, snapshot.settled_microusd), (7, 0))

    def test_narrowing_after_reservation_fences_claim_and_preserves_exposure(self):
        reserved = self.authority.reserve(self.token, read())
        self.authority.narrow_permissions(self.token, frozenset((RELEASE,)))
        denied = self.observe_claim(reserved.ticket)
        self.assertEqual((denied.status, denied.reason), ("denied", "outside_scope"))
        self.assertTrue(self.authority.snapshot(self.token).stopped)
        self.assertEqual(self.authority.snapshot(self.token).reserved_microusd, 7)
        self.assert_no_authorized_dispatch()

    def test_ancestor_narrowing_is_current_for_child_reservation(self):
        child = self.child()
        self.authority.narrow_permissions(self.token, frozenset((RELEASE,)))
        denied = self.authority.reserve(child, read())
        self.assertEqual((denied.status, denied.reason), ("denied", "outside_scope"))
        self.assertTrue(self.authority.snapshot(self.token).stopped)
        self.assert_no_authorized_dispatch()

    def test_rotated_session_invalidates_old_root_and_existing_descendant(self):
        for target in ("old-root", "child"):
            with self.subTest(target=target):
                authority = self.make_authority(path=Path(self.temp.name) / f"session-{target}.sqlite")
                token = authority.admit(self.binding, CONTEXT)
                child = authority.delegate(token, replace(self.binding, session="child", worker="child"),
                                           frozenset((READ,)), CONTEXT)
                new_token = authority.rotate_session(token, "replacement-session")
                denied = authority.reserve(token if target == "old-root" else child, read())
                self.assertEqual(denied.status, "denied")
                self.assertEqual(denied.reason, "binding_mismatch" if target == "old-root"
                                 else "ancestor_binding_mismatch")
                self.assertTrue(authority.snapshot(new_token).stopped)

    def test_typed_unauthorized_participant_stops_children_and_new_admission(self):
        validator = lambda attempt, context: ValidationOutcome.deny("participant_not_authorized")
        authority = self.make_authority(path=Path(self.temp.name) / "typed-denial.sqlite", validator=validator)
        token = authority.admit(self.binding, CONTEXT)
        child = authority.delegate(token, replace(self.binding, session="child", worker="child"),
                                   frozenset((READ,)), CONTEXT)
        denied = authority.reserve(child, read())
        self.assertEqual((denied.status, denied.reason), ("denied", "participant_not_authorized"))
        self.assertTrue(authority.snapshot(token).stopped)
        self.assertEqual(authority.reserve(token, read("root-next")).reason, "root_stopped")
        with self.assertRaisesRegex(DurableError, "root_stopped"):
            authority.delegate(token, self.binding, frozenset((READ,)), CONTEXT)
        self.assertEqual(authority.snapshot(token).calls_used, 0)

    def test_typed_missing_business_input_holds_without_stopping_or_reserving(self):
        validator = lambda attempt, context: ValidationOutcome.hold("participant_details_missing")
        authority = self.make_authority(path=Path(self.temp.name) / "typed-hold.sqlite", validator=validator)
        token = authority.admit(self.binding, CONTEXT)
        held = authority.reserve(token, read())
        self.assertEqual((held.status, held.reason), ("held", "participant_details_missing"))
        snapshot = authority.snapshot(token)
        self.assertFalse(snapshot.stopped)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (0, 0))

    def test_missing_graph_or_required_context_declarations_reject_configuration(self):
        for selected in (replace(contract(), step_dependencies={"inspect": ()}),
                         replace(contract(), required_context={"inspect": ("record",)}),
                         replace(contract(), step_dependencies={"inspect": ("release",),
                                                                 "release": ("inspect",)}),
                         replace(contract(), step_dependencies={"inspect": (),
                                                                 "release": ("undeclared",)})):
            with self.subTest(selected=selected), self.assertRaises(ValueError):
                self.make_authority(path=Path(self.temp.name) / "invalid.sqlite", selected=selected)

    def test_out_of_order_release_stops_without_reservation_or_dispatch(self):
        denied = self.authority.reserve(self.token, release())
        self.assertEqual((denied.status, denied.reason), ("denied", "step_out_of_order"))
        snapshot = self.authority.snapshot(self.token)
        self.assertTrue(snapshot.stopped)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (0, 0))
        self.assert_no_authorized_dispatch()

    def test_missing_required_context_holds_without_money_or_dispatch(self):
        token = self.authority.admit(self.binding, {"task": CONTEXT["task"]})
        held = self.authority.reserve(token, read())
        self.assertEqual((held.status, held.reason), ("held", "missing_context"))
        snapshot = self.authority.snapshot(token)
        self.assertFalse(snapshot.stopped)
        self.assertEqual(snapshot.calls_used, 0)
        self.assert_no_authorized_dispatch()

    def test_stop_before_claim_fences_root_and_child_but_unrelated_root_progresses(self):
        child = self.child()
        reserved = self.authority.reserve(child, read())
        other = self.authority.admit(self.binding, CONTEXT)
        self.authority.reopen().stop_root(self.token)
        denied = self.observe_claim(reserved.ticket)
        self.assertEqual((denied.status, denied.reason), ("denied", "root_stopped"))
        self.assertEqual(self.authority.reserve(child, read("late")).reason, "root_stopped")
        self.assert_no_authorized_dispatch()
        other_reserved = self.authority.reserve(other, read("unrelated"))
        self.assertEqual(self.observe_claim(other_reserved.ticket).status, "allowed")
        self.assertEqual(len(self.effects), 1)

    def test_dispatch_already_committed_can_settle_after_stop_without_new_dispatch(self):
        reserved = self.authority.reserve(self.token, read())
        self.assertEqual(self.observe_claim(reserved.ticket).status, "allowed")
        self.authority.reopen().stop_root(self.token)
        settled = self.authority.settle(reserved.ticket, {"observed": "read-1"}, 5)
        self.assertEqual((settled.status, settled.reason), ("allowed", "settled"))
        self.assertEqual(self.authority.reserve(self.token, read("after-stop")).reason, "root_stopped")
        snapshot = self.authority.snapshot(self.token)
        self.assertTrue(snapshot.stopped)
        self.assertEqual((snapshot.reserved_microusd, snapshot.settled_microusd), (0, 5))
        self.assertEqual(len(self.effects), 1)

    def test_receiver_recipient_mismatch_stops_without_dispatch(self):
        reserved = self.authority.reserve(self.token, read())
        denied = self.observe_claim(reserved.ticket, recipients=frozenset(("other-reader",)))
        self.assertEqual((denied.status, denied.reason), ("denied", "receiver_scope_mismatch"))
        self.assertTrue(self.authority.snapshot(self.token).stopped)
        self.assert_no_authorized_dispatch()

    def test_duplicate_reservation_does_not_consume_or_lose_exact_approval(self):
        selected = replace(contract(), exact_approval_actions=frozenset(("source.read",)))
        authority = self.make_authority(path=Path(self.temp.name) / "approval.sqlite", selected=selected)
        token = authority.admit(self.binding, CONTEXT)
        self.assertEqual(authority.reserve(token, read()).reason, "approval_required")
        approval = authority.issue_approval(token, read())
        first = authority.reserve(token, read(), approval_id=approval)
        repeat = authority.reserve(token, read(), approval_id=approval)
        self.assertEqual((repeat.ticket, repeat.replayed), (first.ticket, True))
        self.assertEqual(authority.claim(first.ticket).status, "allowed")
        self.assertEqual(authority.settle(first.ticket, {"observed": "read-1"}, 5).status, "allowed")
        self.assertEqual(authority.snapshot(token).calls_used, 1)
        self.assertEqual(authority.reserve(token, read("different"), approval_id=approval).reason,
                         "invalid_approval")
        self.assertTrue(authority.snapshot(token).stopped)

    def test_reserved_audit_exists_only_for_committed_budget_reservation(self):
        authority = self.make_authority(path=Path(self.temp.name) / "audit.sqlite", budget=7)
        token = authority.admit(self.binding, CONTEXT)
        first = authority.reserve(token, read())
        self.assertEqual(authority.reserve(token, read("exhausted")).reason, "budget_exhausted")
        with sqlite3.connect(authority.path) as connection:
            observed = connection.execute("SELECT ticket FROM audit WHERE event='reserved'").fetchall()
            actual = connection.execute("SELECT ticket FROM operations").fetchall()
        self.assertEqual(observed, [(first.ticket,)])
        self.assertEqual(observed, actual)

    def test_slow_validator_allows_prompt_stop_and_rechecks_before_reserving(self):
        entered, release_validator, stopped = threading.Event(), threading.Event(), threading.Event()
        def validator(attempt, context):
            entered.set()
            if not release_validator.wait(5):
                raise RuntimeError("test validator timed out")
            return ValidationOutcome.allow()
        authority = self.make_authority(path=Path(self.temp.name) / "slow.sqlite", validator=validator)
        token = authority.admit(self.binding, CONTEXT)
        separate = authority.reopen()
        with ThreadPoolExecutor(max_workers=2) as pool:
            reservation = pool.submit(authority.reserve, token, read())
            self.assertTrue(entered.wait(2), "validator did not enter")
            def stop():
                separate.stop_root(token)
                stopped.set()
            stopping = pool.submit(stop)
            try:
                self.assertTrue(stopped.wait(1), "Stop blocked behind business validator")
            finally:
                release_validator.set()
            stopping.result(timeout=2)
            result = reservation.result(timeout=2)
        self.assertEqual((result.status, result.reason), ("denied", "root_stopped"))
        snapshot = authority.snapshot(token)
        self.assertTrue(snapshot.stopped)
        self.assertEqual((snapshot.calls_used, snapshot.exposure_microusd), (0, 0))

    def test_slow_claim_validator_allows_stop_and_never_authorizes_effect(self):
        entered, release_validator, stopped = threading.Event(), threading.Event(), threading.Event()
        calls = 0
        def validator(attempt, context):
            nonlocal calls
            calls += 1
            if calls == 2:  # reserve was checked; receiving-side revalidation blocks.
                entered.set()
                if not release_validator.wait(5):
                    raise RuntimeError("test validator timed out")
            return ValidationOutcome.allow()
        authority = self.make_authority(path=Path(self.temp.name) / "slow-claim.sqlite", validator=validator)
        token = authority.admit(self.binding, CONTEXT)
        reserved = authority.reserve(token, read())
        self.assertEqual(reserved.status, "reserved")
        separate = authority.reopen()
        with ThreadPoolExecutor(max_workers=2) as pool:
            claiming = pool.submit(authority.claim, reserved.ticket)
            self.assertTrue(entered.wait(2), "claim validator did not enter")
            def stop():
                separate.stop_root(token)
                stopped.set()
            stopping = pool.submit(stop)
            try:
                self.assertTrue(stopped.wait(1), "Stop blocked behind claim validator")
            finally:
                release_validator.set()
            stopping.result(timeout=2)
            result = claiming.result(timeout=2)
        self.assertEqual((result.status, result.reason, result.dispatch), ("denied", "root_stopped", None))
        snapshot = authority.snapshot(token)
        self.assertEqual((snapshot.calls_used, snapshot.reserved_microusd), (1, 7))
        self.assertEqual(snapshot.unknown_operations, ())
        with sqlite3.connect(authority.path) as connection:
            self.assertEqual(connection.execute(
                "SELECT count(*) FROM audit WHERE event='dispatch_authorized'").fetchone()[0], 0)

    def test_forged_or_untyped_validator_outcome_fails_closed(self):
        forged = object.__new__(ValidationOutcome)
        object.__setattr__(forged, "status", "allow")
        object.__setattr__(forged, "reason", "sensitive invalid reason")
        for index, outcome in enumerate((None, "allowed", forged)):
            authority = self.make_authority(
                path=Path(self.temp.name) / f"invalid-validator-{index}.sqlite",
                validator=lambda attempt, context, selected=outcome: selected)
            token = authority.admit(self.binding, CONTEXT)
            result = authority.reserve(token, read())
            self.assertEqual((result.status, result.reason), ("denied", "validator_result_invalid"))
            snapshot = authority.snapshot(token)
            self.assertTrue(snapshot.stopped)
            self.assertEqual(snapshot.calls_used, 0)

    def test_receipt_release_rechecks_stop_and_epoch_without_losing_settlement(self):
        ticket = self.complete()
        released = self.authority.release_result(ticket)
        self.assertEqual((released.status, dict(released.receipt)),
                         ("allowed", {"observed": "read-1"}))
        replacement = self.authority.reopen().activate()
        self.assertEqual(replacement.release_result(ticket).reason, "stale_result_binding")
        replacement.stop_root(self.token)
        denied = replacement.release_result(ticket)
        self.assertEqual((denied.status, denied.reason, denied.receipt), ("denied", "root_stopped", None))
        self.assertEqual(replacement.snapshot(self.token).settled_microusd, 5)

    def test_new_epoch_reconciles_already_dispatched_receipt_without_replaying_effect(self):
        reserved = self.authority.reserve(self.token, read())
        self.assertEqual(self.observe_claim(reserved.ticket).status, "allowed")
        replacement = self.authority.reopen().activate()
        self.assertEqual(replacement.claim(reserved.ticket).reason, "ticket_fenced")
        settled = replacement.settle(reserved.ticket, {"observed": "read-1"}, 5)
        self.assertEqual((settled.status, settled.reason), ("allowed", "settled"))
        self.assertEqual(replacement.release_result(reserved.ticket).reason, "stale_result_binding")
        self.assertEqual(replacement.snapshot(self.token).exposure_microusd, 5)
        self.assertEqual(len(self.effects), 1)


if __name__ == "__main__":
    unittest.main()
