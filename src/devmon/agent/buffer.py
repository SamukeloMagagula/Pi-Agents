from __future__ import annotations

from typing import Dict, List, Optional


class Outbox:
    """Messages the hub has not yet confirmed, kept for at most max_age_s.

    Every message gets a `seq` number when added. A message stays here after it is
    sent and leaves only when the hub acknowledges its seq (acks are cumulative), so
    anything written into a connection that silently died (a laptop going to sleep)
    is sent again after the reconnect. The hub ignores the copies it already stored.
    """

    def __init__(self, max_age_s: float = 600) -> None:
        self.max_age_s = max_age_s
        self._items: List[Dict] = []  # in seq order
        self._sent_at: Dict[int, float] = {}
        self._next_seq = 1

    def add(self, msg: dict) -> dict:
        """Number the message, keep it, and return it."""
        msg["seq"] = self._next_seq
        self._next_seq += 1
        # Prune on every add so a long outage cannot grow memory without limit.
        self._prune(msg["ts"])
        self._items.append(msg)
        return msg

    def pending(self, now: float, after: int = 0) -> List[Dict]:
        """Unconfirmed messages no older than max_age_s with seq > after, oldest first."""
        self._prune(now)
        return [m for m in self._items if m["seq"] > after]

    def mark_sent(self, seq: int, now: float) -> None:
        self._sent_at[seq] = now

    def ack(self, seq: int) -> None:
        """The hub has everything up to and including seq."""
        self._items = [m for m in self._items if m["seq"] > seq]
        self._sent_at = {s: t for s, t in self._sent_at.items() if s > seq}

    def discard(self, seq: int) -> None:
        """Forget one message that can never be delivered (e.g. too large)."""
        self._items = [m for m in self._items if m["seq"] != seq]
        self._sent_at.pop(seq, None)

    def oldest_unconfirmed_send(self) -> Optional[float]:
        """When the oldest still-unconfirmed message was last sent, or None."""
        return min(self._sent_at.values()) if self._sent_at else None

    def forget_sends(self) -> None:
        """A connection ended: nothing is in flight any more."""
        self._sent_at = {}

    def _prune(self, now: float) -> None:
        cutoff = now - self.max_age_s
        kept = [m for m in self._items if m["ts"] >= cutoff]
        if len(kept) != len(self._items):
            live = {m["seq"] for m in kept}
            self._sent_at = {s: t for s, t in self._sent_at.items() if s in live}
            self._items = kept

    def __len__(self) -> int:
        return len(self._items)
