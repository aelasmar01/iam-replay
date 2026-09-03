"""Three-valued evaluation of IAM condition blocks (spec §7).

Every condition evaluates to TRUE, FALSE, or UNEVALUABLE. The third value is
the reason this tool exists: a condition key missing from the extracted context
is a fact about *the log*, not about the request. CloudTrail may simply not have
recorded a key that was present when the call was authorized.

That distinction drives a deliberate divergence from AWS's own semantics. Under
real IAM evaluation:

* ``Null`` on an absent key evaluates TRUE (the key really is absent),
* ``...IfExists`` on an absent key evaluates TRUE (the check is skipped),
* ``ForAllValues:`` on an absent key evaluates TRUE (vacuously, over an empty
  set -- a documented security gotcha in its own right).

All three are UNEVALUABLE here instead, because "absent from the event" and
"absent from the request" are not the same claim, and only the second one would
justify those answers. Emulating AWS on an incomplete context would produce
confident verdicts from missing data, which is precisely the failure mode the
three-state output exists to prevent.

An operator this module does not implement is UNEVALUABLE, never TRUE. A
silently-true unknown operator would evaluate a Deny away.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Mapping

from ..models import ContextValue
from .arn import glob_match


class Tri(str, Enum):
    """A three-valued truth for a condition, statement, or policy."""

    TRUE = "TRUE"
    FALSE = "FALSE"
    UNEVALUABLE = "UNEVALUABLE"


@dataclass(frozen=True)
class ConditionResult:
    """The outcome of a condition block, with the keys that defeated it."""

    value: Tri
    #: Condition keys that could not be evaluated. Named in the report so the
    #: user learns *which* key defeated the evaluation, not merely that one did.
    unevaluable_keys: tuple[str, ...] = field(default_factory=tuple)
    #: Human-readable explanations, e.g. an unsupported operator.
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def is_true(self) -> bool:
        return self.value is Tri.TRUE

    @property
    def is_unevaluable(self) -> bool:
        return self.value is Tri.UNEVALUABLE


TRUE = ConditionResult(Tri.TRUE)
FALSE = ConditionResult(Tri.FALSE)


# --- scalar comparisons ------------------------------------------------------
#
# Each returns True/False, or raises _Unevaluable when the comparison itself
# cannot be carried out (a non-numeric value under a Numeric operator, say).


class _Unevaluable(Exception):
    """Raised when a comparison cannot be performed on the given values."""


def _as_number(value: str) -> float:
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise _Unevaluable(f"{value!r} is not numeric") from exc


def _as_datetime(value: str) -> datetime:
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromtimestamp(float(text), tz=timezone.utc)
        except (TypeError, ValueError) as exc:
            raise _Unevaluable(f"{value!r} is not a date") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _as_bool(value: str) -> bool:
    text = str(value).strip().lower()
    if text in {"true", "false"}:
        return text == "true"
    raise _Unevaluable(f"{value!r} is not a boolean")


def _as_network(value: str) -> Any:
    try:
        return ipaddress.ip_network(str(value), strict=False)
    except ValueError as exc:
        raise _Unevaluable(f"{value!r} is not a CIDR block") from exc


def _as_address(value: str) -> Any:
    try:
        return ipaddress.ip_address(str(value))
    except ValueError as exc:
        raise _Unevaluable(f"{value!r} is not an IP address") from exc


def _ip_in(context_value: str, policy_value: str) -> bool:
    address = _as_address(context_value)
    network = _as_network(policy_value)
    if address.version != network.version:
        return False
    return address in network


#: Base operators, before Not-/ForAllValues:/ForAnyValue:/IfExists decoration.
#: Every comparison takes (context_value, policy_value).
_COMPARISONS: dict[str, Callable[[str, str], bool]] = {
    "StringEquals": lambda c, p: c == p,
    "StringEqualsIgnoreCase": lambda c, p: c.casefold() == p.casefold(),
    "StringLike": lambda c, p: glob_match(p, c, case_sensitive=True),
    "NumericEquals": lambda c, p: _as_number(c) == _as_number(p),
    "NumericLessThan": lambda c, p: _as_number(c) < _as_number(p),
    "NumericLessThanEquals": lambda c, p: _as_number(c) <= _as_number(p),
    "NumericGreaterThan": lambda c, p: _as_number(c) > _as_number(p),
    "NumericGreaterThanEquals": lambda c, p: _as_number(c) >= _as_number(p),
    "DateEquals": lambda c, p: _as_datetime(c) == _as_datetime(p),
    "DateLessThan": lambda c, p: _as_datetime(c) < _as_datetime(p),
    "DateLessThanEquals": lambda c, p: _as_datetime(c) <= _as_datetime(p),
    "DateGreaterThan": lambda c, p: _as_datetime(c) > _as_datetime(p),
    "DateGreaterThanEquals": lambda c, p: _as_datetime(c) >= _as_datetime(p),
    "Bool": lambda c, p: _as_bool(c) == _as_bool(p),
    "IpAddress": _ip_in,
    # ArnEquals and ArnLike are equivalent in IAM: both permit wildcards in the
    # policy value. They are kept as separate names so a policy reads back the
    # way it was written.
    "ArnEquals": lambda c, p: glob_match(p, c, case_sensitive=True),
    "ArnLike": lambda c, p: glob_match(p, c, case_sensitive=True),
    "BinaryEquals": lambda c, p: c == p,
}

#: Negated forms. Each is its positive counterpart with the result inverted,
#: applied *after* the multi-value quantifier so that ForAllValues:StringNotEquals
#: means "no value matches", matching IAM.
_NEGATIONS = {
    "StringNotEquals": "StringEquals",
    "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
    "StringNotLike": "StringLike",
    "NumericNotEquals": "NumericEquals",
    "DateNotEquals": "DateEquals",
    "NotIpAddress": "IpAddress",
    "ArnNotEquals": "ArnEquals",
    "ArnNotLike": "ArnLike",
    "BinaryNotEquals": "BinaryEquals",
}


@dataclass(frozen=True)
class _Operator:
    base: str
    negated: bool
    quantifier: str | None  # "ForAllValues" | "ForAnyValue" | None
    if_exists: bool


def parse_operator(raw: str) -> _Operator | None:
    """Split ``ForAnyValue:StringNotLikeIfExists`` into its parts.

    Returns None for an operator this module does not implement, which the
    caller must treat as UNEVALUABLE rather than as a passing check.
    """
    quantifier: str | None = None
    name = raw
    if ":" in name:
        prefix, _, rest = name.partition(":")
        if prefix in {"ForAllValues", "ForAnyValue"}:
            quantifier, name = prefix, rest
        else:
            return None

    if_exists = name.endswith("IfExists")
    if if_exists:
        name = name[: -len("IfExists")]

    if name in _NEGATIONS:
        return _Operator(_NEGATIONS[name], True, quantifier, if_exists)
    if name in _COMPARISONS:
        return _Operator(name, False, quantifier, if_exists)
    return None


def _policy_values(raw: Any) -> list[str]:
    if isinstance(raw, list):
        return [str(v) for v in raw]
    if isinstance(raw, bool):
        return ["true" if raw else "false"]
    return [str(raw)]


def _matches_any_policy_value(
    compare: Callable[[str, str], bool], context_value: str, policy_values: list[str]
) -> bool:
    """Policy values under one key are OR'd together (IAM semantics)."""
    return any(compare(context_value, policy_value) for policy_value in policy_values)


def _evaluate_single_key(
    operator: _Operator,
    context_values: ContextValue,
    policy_values: list[str],
) -> bool:
    compare = _COMPARISONS[operator.base]

    if operator.quantifier == "ForAllValues":
        # Every value in the request key must match at least one policy value.
        result = all(
            _matches_any_policy_value(compare, value, policy_values)
            for value in context_values
        )
    elif operator.quantifier == "ForAnyValue":
        result = any(
            _matches_any_policy_value(compare, value, policy_values)
            for value in context_values
        )
    else:
        # No quantifier. Single-valued keys are the normal case; a multi-valued
        # key here is treated as ForAnyValue, which is how IAM behaves when a
        # single-valued operator meets a multi-valued key.
        result = any(
            _matches_any_policy_value(compare, value, policy_values)
            for value in context_values
        )

    return not result if operator.negated else result


def evaluate(
    condition_block: Mapping[str, Any] | None,
    context: Mapping[str, ContextValue],
) -> ConditionResult:
    """Evaluate a statement's whole Condition block against an event context.

    All operators in the block are AND'd, and all keys within one operator are
    AND'd; only the values under a single key are OR'd. A single UNEVALUABLE
    makes the whole block UNEVALUABLE unless something else already made it
    definitively FALSE -- a block that cannot apply is a useful answer even when
    part of it is unknown.
    """
    if not condition_block:
        return TRUE

    unevaluable_keys: list[str] = []
    notes: list[str] = []
    definitely_false = False

    for raw_operator, key_map in condition_block.items():
        if str(raw_operator) == "Null":
            outcome, keys = _evaluate_null(key_map or {}, context)
            if outcome is Tri.FALSE:
                definitely_false = True
            unevaluable_keys.extend(keys)
            continue

        operator = parse_operator(str(raw_operator))
        if operator is None:
            # Never assume an unknown operator passes: that would evaluate an
            # explicit Deny away.
            unevaluable_keys.extend(str(k) for k in (key_map or {}))
            notes.append(f"unsupported condition operator {raw_operator!r}")
            continue

        for key, raw_policy_values in (key_map or {}).items():
            key = str(key)
            context_values = _lookup(context, key)

            if context_values is None:
                # See the module docstring: absent from the log is not absent
                # from the request, so Null, IfExists and ForAllValues do not
                # get their usual free pass.
                unevaluable_keys.append(key)
                continue

            try:
                holds = _evaluate_single_key(
                    operator, context_values, _policy_values(raw_policy_values)
                )
            except _Unevaluable as exc:
                unevaluable_keys.append(key)
                notes.append(f"{key}: {exc}")
                continue

            if not holds:
                definitely_false = True

    if definitely_false:
        return ConditionResult(Tri.FALSE, tuple(dict.fromkeys(unevaluable_keys)), tuple(notes))
    if unevaluable_keys:
        return ConditionResult(
            Tri.UNEVALUABLE, tuple(dict.fromkeys(unevaluable_keys)), tuple(notes)
        )
    return TRUE


def _evaluate_null(
    key_map: Mapping[str, Any], context: Mapping[str, ContextValue]
) -> tuple[Tri, list[str]]:
    """Evaluate a ``Null`` block, which tests for a key's presence.

    Only half of this operator is answerable from a CloudTrail event. When the
    key *is* in the context, its presence is established fact and both
    directions resolve confidently. When it is absent, we cannot tell whether
    the request lacked the key or the log merely omitted it, so the check is
    UNEVALUABLE -- unlike real IAM, where absence makes ``Null: true`` pass.
    """
    unevaluable: list[str] = []
    result = Tri.TRUE

    for key, raw in key_map.items():
        key = str(key)
        must_be_absent = str(raw).strip().lower() == "true"
        present = _lookup(context, key) is not None

        if present:
            # Presence is a fact the event proves, so this resolves either way.
            if must_be_absent:
                result = Tri.FALSE
        else:
            unevaluable.append(key)

    return result, unevaluable



def _lookup(context: Mapping[str, ContextValue], key: str) -> ContextValue | None:
    """Look up a condition key case-insensitively, as IAM does."""
    if key in context:
        return context[key]
    folded = key.casefold()
    for candidate, value in context.items():
        if candidate.casefold() == folded:
            return value
    return None


def referenced_keys(condition_block: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Every condition key a block depends on, for reporting."""
    if not condition_block:
        return ()
    keys: list[str] = []
    for key_map in condition_block.values():
        keys.extend(str(k) for k in (key_map or {}))
    return tuple(dict.fromkeys(keys))
