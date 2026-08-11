"""Bounded, deterministic proof of exact-replacement occurrence alignment."""

from __future__ import annotations

from dataclasses import dataclass

MAX_OCCURRENCE_ALIGNMENT_CELLS = 4_000_000


@dataclass(frozen=True, slots=True)
class TextSpan:
    """A half-open text span."""

    start: int
    end: int


@dataclass(frozen=True, slots=True)
class OccurrenceAnchor:
    """One declared baseline span and its candidate replacement span."""

    before: TextSpan
    after: TextSpan


@dataclass(slots=True)
class AlignmentBudget:
    """A verdict-wide cap on alignment cells."""

    remaining_cells: int = MAX_OCCURRENCE_ALIGNMENT_CELLS


@dataclass(frozen=True, slots=True)
class _State:
    cost: int
    required_by_all: int


def _merge(current: _State | None, candidate: _State) -> _State:
    if current is None or candidate.cost < current.cost:
        return candidate
    if candidate.cost == current.cost:
        return _State(
            cost=current.cost,
            required_by_all=current.required_by_all & candidate.required_by_all,
        )
    return current


def _valid_span(span: TextSpan, limit: int) -> bool:
    return type(span.start) is int and type(span.end) is int and 0 <= span.start < span.end <= limit


def _valid_anchors(
    before_text: str,
    after_text: str,
    anchors: tuple[OccurrenceAnchor, ...],
) -> bool:
    if not anchors:
        return False
    previous: OccurrenceAnchor | None = None
    for anchor in anchors:
        if not _valid_span(anchor.before, len(before_text)) or not _valid_span(
            anchor.after, len(after_text)
        ):
            return False
        if previous is not None and (
            previous.before.end > anchor.before.start or previous.after.end > anchor.after.start
        ):
            return False
        previous = anchor
    return True


def prove_atomic_occurrence_alignment(
    before_text: str,
    after_text: str,
    anchors: tuple[OccurrenceAnchor, ...],
    budget: AlignmentBudget,
) -> bool:
    """Return true only when every minimum-cost alignment uses every anchor."""
    if not _valid_anchors(before_text, after_text, anchors):
        return False
    cells = (len(before_text) + 1) * (len(after_text) + 1)
    if type(budget.remaining_cells) is not int or cells > budget.remaining_cells:
        return False
    budget.remaining_cells -= cells

    sources = {
        (anchor.before.start, anchor.after.start): (index, anchor)
        for index, anchor in enumerate(anchors)
    }
    pending: dict[tuple[int, int], _State] = {}
    previous: list[_State | None] = [None] * (len(after_text) + 1)

    for before_index in range(len(before_text) + 1):
        current: list[_State | None] = [None] * (len(after_text) + 1)
        for after_index in range(len(after_text) + 1):
            state = pending.pop((before_index, after_index), None)
            if before_index == 0 and after_index == 0:
                state = _merge(state, _State(cost=0, required_by_all=0))
            if before_index > 0:
                above = previous[after_index]
                if above is not None:
                    state = _merge(
                        state,
                        _State(above.cost + 1, above.required_by_all),
                    )
            if after_index > 0:
                left = current[after_index - 1]
                if left is not None:
                    state = _merge(
                        state,
                        _State(left.cost + 1, left.required_by_all),
                    )
            if before_index > 0 and after_index > 0:
                diagonal = previous[after_index - 1]
                if diagonal is not None:
                    substitution_cost = before_text[before_index - 1] != after_text[after_index - 1]
                    state = _merge(
                        state,
                        _State(
                            diagonal.cost + substitution_cost,
                            diagonal.required_by_all,
                        ),
                    )
            current[after_index] = state

            source = sources.get((before_index, after_index))
            if state is not None and source is not None:
                anchor_index, anchor = source
                destination = (anchor.before.end, anchor.after.end)
                anchored = _State(
                    cost=state.cost,
                    required_by_all=state.required_by_all | (1 << anchor_index),
                )
                pending[destination] = _merge(pending.get(destination), anchored)
        previous = current

    terminal = previous[-1]
    required = (1 << len(anchors)) - 1
    return terminal is not None and terminal.required_by_all == required
