from __future__ import annotations

from devmon.agent.buffer import Outbox


def _msg(ts, n=0):
    return {"type": "metrics", "ts": ts, "n": n}


def test_messages_are_numbered_from_one():
    box = Outbox()
    assert [box.add(_msg(1000.0 + i))["seq"] for i in range(3)] == [1, 2, 3]


def test_messages_aged_past_the_limit_are_dropped():
    box = Outbox()
    box.add(_msg(1000.0, 1))  # 700 s old at 1700
    box.add(_msg(1500.0, 2))  # 200 s old
    assert [m["n"] for m in box.pending(1700.0)] == [2]
    assert len(box) == 1


def test_message_exactly_max_age_old_is_kept():
    box = Outbox(max_age_s=600)
    box.add(_msg(1100.0))
    assert len(box.pending(1700.0)) == 1


def test_pending_keeps_messages_until_acked():
    box = Outbox()
    for n in range(4):
        box.add(_msg(1000.0 + 10 * n, n))
    assert [m["n"] for m in box.pending(1100.0)] == [0, 1, 2, 3]
    # Still there: sending does not remove anything.
    assert len(box.pending(1100.0)) == 4
    box.ack(2)  # cumulative: seq 1 and 2
    assert [m["seq"] for m in box.pending(1100.0)] == [3, 4]


def test_pending_after_skips_what_was_already_sent():
    box = Outbox()
    for n in range(4):
        box.add(_msg(1000.0 + n, n))
    assert [m["seq"] for m in box.pending(1010.0, after=2)] == [3, 4]


def test_pending_is_in_seq_order_even_when_ts_is_not():
    box = Outbox()
    box.add(_msg(1020.0, 1))  # a database reading stamped before a slow query finished
    box.add(_msg(1010.0, 2))
    assert [m["n"] for m in box.pending(1030.0)] == [1, 2]


def test_discard_removes_one_message():
    box = Outbox()
    for n in range(3):
        box.add(_msg(1000.0, n))
    box.discard(2)
    assert [m["seq"] for m in box.pending(1000.0)] == [1, 3]


def test_oldest_unconfirmed_send_tracks_sends_and_acks():
    box = Outbox()
    for n in range(3):
        box.add(_msg(1000.0 + n, n))
    assert box.oldest_unconfirmed_send() is None
    box.mark_sent(1, 1000.0)
    box.mark_sent(2, 1010.0)
    box.mark_sent(3, 1020.0)
    assert box.oldest_unconfirmed_send() == 1000.0
    box.ack(1)
    assert box.oldest_unconfirmed_send() == 1010.0
    box.forget_sends()
    assert box.oldest_unconfirmed_send() is None
    assert len(box) == 2  # forgetting sends keeps the messages


def test_pruned_messages_stop_counting_as_sent():
    box = Outbox(max_age_s=600)
    box.add(_msg(1000.0))
    box.mark_sent(1, 1000.0)
    box.pending(1700.0)
    assert box.oldest_unconfirmed_send() is None


def test_add_prunes_old_messages_during_a_long_outage():
    box = Outbox(max_age_s=600)
    for n in range(200):  # 2000 s of 10-second ticks
        box.add(_msg(10.0 * n, n))
    assert len(box) == 61  # ts 1390 .. 1990
