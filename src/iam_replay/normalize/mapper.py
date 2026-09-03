"""Map a CloudTrail event to the authorization requests it represents (§6).

This is the novel, high-risk component of the tool. The evaluation engine
implements logic AWS documents publicly; nothing publishes the
``eventName -> IAM action -> resource ARN`` correspondence, so it is written by
hand here and validated by the ground-truth oracle (§9.1) rather than by
hand-written expectations, which would only prove the mapper matches its
author's beliefs.

Three rules do the heavy lifting:

* ``eventName`` is **not** the IAM action. ``ListObjectsV2`` authorizes
  ``s3:ListBucket``. Every event is mapped explicitly; nothing is derived.
* A template referencing a field the event does not carry yields
  ``resource_arn = None`` and ``UNKNOWN_RESOURCE``. Never a guess, never ``*``.
* Some APIs require no IAM permission at all. Mapping those to an action would
  make a tight policy produce a false DENY, so they are excluded outright.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from ..models import (
    AuthorizationRequest,
    Confidence,
    EventMeta,
    MappedEvent,
    Reason,
    freeze_context,
)
from . import context as context_module
from .outcome import classify, error_code_of
from .principal import resolve

#: Frozen for v1 (spec §6). Anything outside resolves to INDETERMINATE with
#: reason ``unsupported_service`` -- a correct answer, not a failure.
SERVICE_ALLOWLIST = frozenset({"s3", "iam", "sts", "ec2", "lambda", "kms"})

MAPPINGS_DIR = Path(__file__).parent / "mappings"

_TEMPLATE_FIELD = re.compile(r"\{([^}]+)\}")


@dataclass(frozen=True)
class _Permission:
    """One (action, resource-template) pair declared in a mapping file."""

    action: str
    resource: str | None
    resource_type: str | None = None
    #: Substring that picks one entry out of ``resources[]`` when CloudTrail
    #: types several entries identically. KMS labels both the alias and the key
    #: as ``AWS::KMS::Key`` on the same event, so the type is useless there and
    #: the ARN's own resource section is the only thing that separates them.
    resource_arn_contains: str | None = None
    #: True when the API accepts either a bare name or a full ARN in the same
    #: request field (lambda functionName, kms keyId). When the event carries an
    #: ARN, it is used verbatim instead of being substituted into the template,
    #: which would otherwise produce a nested ARN like
    #: "arn:aws:lambda:...:function:arn:aws:lambda:...".
    resource_may_be_arn: bool = False
    note: str | None = None


@dataclass(frozen=True)
class _EventMapping:
    permissions: tuple[_Permission, ...]
    requires_no_authorization: bool = False
    #: True when the event authorizes several distinct permissions, e.g.
    #: ec2:RunInstances. Every expanded entry is marked INFERRED because the
    #: event does not state the expansion; the mapping asserts it.
    is_expansion: bool = False


def service_from_event_source(event_source: str) -> str | None:
    """``s3.amazonaws.com`` -> ``s3``. Returns None for an unparsable source."""
    if not event_source:
        return None
    prefix = event_source.split(".", 1)[0].strip().lower()
    return prefix or None


def partition_for_region(region: str) -> str:
    """Derive the ARN partition from a region so templates stay portable.

    Hardcoding ``arn:aws:`` would silently build wrong ARNs in GovCloud and
    China, where every resource ARN would then fail to match a correct policy.
    """
    region = (region or "").lower()
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


def _dotted_get(event: dict[str, Any], path: str) -> Any:
    """Read ``requestParameters.bucketName`` out of an event. None if absent.

    A numeric segment indexes into a list, so nested request shapes such as
    ``requestParameters.instancesSet.items.0.imageId`` are reachable.
    """
    current: Any = event
    for part in path.split("."):
        if isinstance(current, list):
            if not part.isdigit() or int(part) >= len(current):
                return None
            current = current[int(part)]
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _verbatim_arn(template: str, event: dict[str, Any]) -> str | None:
    """Return the field's value when it is already a full ARN.

    Only consulted for mappings that set ``resource_may_be_arn``. Substituting
    an ARN into an ARN template builds a resource that matches nothing.
    """
    for field_path in _TEMPLATE_FIELD.findall(template):
        value = _dotted_get(event, field_path)
        if isinstance(value, str) and value.startswith("arn:"):
            return value
    return None

def _load_mappings(directory: Path) -> dict[str, dict[str, _EventMapping]]:
    mappings: dict[str, dict[str, _EventMapping]] = {}
    for path in sorted(directory.glob("*.yaml")):
        document = yaml.safe_load(path.read_text()) or {}
        service = document.get("service")
        if not service:
            raise ValueError(f"{path} has no 'service' key")

        events: dict[str, _EventMapping] = {}
        for event_name, spec in (document.get("events") or {}).items():
            events[event_name] = _parse_event_mapping(spec, path, event_name)
        mappings[service] = events
    return mappings


def _parse_event_mapping(spec: Any, path: Path, event_name: str) -> _EventMapping:
    if not isinstance(spec, dict):
        raise ValueError(f"{path}: mapping for {event_name} must be a mapping")

    if spec.get("requires_no_authorization"):
        return _EventMapping(permissions=(), requires_no_authorization=True)

    if "expands_to" in spec:
        entries = spec["expands_to"] or []
        permissions = tuple(_parse_permission(e, path, event_name) for e in entries)
        # A single-entry expands_to is still an explicit assertion by the
        # mapping author rather than something the event states, so it counts
        # as an expansion and is marked INFERRED.
        return _EventMapping(permissions=permissions, is_expansion=True)

    return _EventMapping(permissions=(_parse_permission(spec, path, event_name),))


def _parse_permission(entry: Any, path: Path, event_name: str) -> _Permission:
    if not isinstance(entry, dict) or "action" not in entry:
        raise ValueError(f"{path}: {event_name} entry needs an 'action'")
    return _Permission(
        action=entry["action"],
        resource=entry.get("resource"),
        resource_type=entry.get("resource_type"),
        resource_arn_contains=entry.get("resource_arn_contains"),
        resource_may_be_arn=bool(entry.get("resource_may_be_arn")),
        note=entry.get("note"),
    )


def _resource_from_event_array(
    event: dict[str, Any],
    resource_type: str | None,
    arn_contains: str | None = None,
) -> str | None:
    """Prefer CloudTrail's own ``resources[]`` annotation over the template.

    It is often strictly better -- for IAM it carries the role's full path,
    which ``requestParameters.roleName`` cannot supply. But an event can list
    several resources of different types, and picking the wrong one produces a
    confidently wrong ARN. So an entry is used only when the mapping names the
    type it wants, or when there is exactly one candidate and no ambiguity.
    """
    resources = event.get("resources")
    if not isinstance(resources, list) or not resources:
        return None

    candidates = [r for r in resources if isinstance(r, dict) and r.get("ARN")]
    if not candidates:
        return None

    if arn_contains:
        matching = [r for r in candidates if arn_contains in r["ARN"]]
        return matching[0]["ARN"] if len(matching) == 1 else None

    if resource_type:
        typed = [r for r in candidates if r.get("type") == resource_type]
        if len(typed) == 1:
            return typed[0]["ARN"]
        return None

    if len(candidates) == 1:
        return candidates[0]["ARN"]
    return None


def _render_template(template: str, event: dict[str, Any]) -> tuple[str | None, list[str]]:
    """Fill a resource template from the event. Returns (arn, missing_fields)."""
    missing: list[str] = []
    partition = partition_for_region(event.get("awsRegion") or "")
    pseudo = {
        "partition": partition,
        "region": event.get("awsRegion") or "",
        "account": (
            event.get("recipientAccountId")
            or (event.get("userIdentity") or {}).get("accountId")
            or ""
        ),
    }

    def substitute(match: re.Match[str]) -> str:
        field_path = match.group(1)
        if field_path in pseudo:
            value = pseudo[field_path]
        else:
            value = _dotted_get(event, field_path)
        if value is None or value == "":
            missing.append(field_path)
            return ""
        return str(value)

    rendered = _TEMPLATE_FIELD.sub(substitute, template)
    if missing:
        return None, missing
    return rendered, []


class Mapper:
    """Maps CloudTrail events to authorization requests using the YAML mappings."""

    def __init__(self, mappings_dir: Path | None = None) -> None:
        self._mappings = _load_mappings(mappings_dir or MAPPINGS_DIR)

    @property
    def supported_services(self) -> frozenset[str]:
        return frozenset(self._mappings)

    def map_event(self, event: dict[str, Any]) -> MappedEvent:
        meta = self._build_meta(event)

        # Resolved before any early return: --principal filtering needs to know
        # who an unmapped or unsupported event belongs to, or every such event
        # in the account matches every principal.
        principal = resolve(event.get("userIdentity"))
        owner = principal.arn

        service = service_from_event_source(event.get("eventSource") or "")
        if service is None or service not in SERVICE_ALLOWLIST:
            return MappedEvent(meta, reason=Reason.UNSUPPORTED_SERVICE, principal_arn=owner)

        event_mapping = self._mappings.get(service, {}).get(meta.event_name)
        if event_mapping is None:
            return MappedEvent(meta, reason=Reason.UNMAPPED_EVENT, principal_arn=owner)

        if event_mapping.requires_no_authorization:
            return MappedEvent(
                meta, reason=Reason.NO_AUTHORIZATION_REQUIRED, principal_arn=owner
            )

        if principal.arn is None:
            return MappedEvent(meta, reason=Reason.UNKNOWN_PRINCIPAL, principal_arn=None)

        frozen_context = freeze_context(context_module.extract(event, principal))

        requests = tuple(
            self._build_request(permission, event, principal, frozen_context, event_mapping)
            for permission in event_mapping.permissions
        )
        return MappedEvent(meta, requests=requests, principal_arn=owner)

    def _build_request(
        self,
        permission: _Permission,
        event: dict[str, Any],
        principal: Any,
        frozen_context: tuple[tuple[str, tuple[str, ...]], ...],
        event_mapping: _EventMapping,
    ) -> AuthorizationRequest:
        notes: list[str] = list(principal.notes)
        inferred = principal.inferred

        if event_mapping.is_expansion:
            inferred = True
            notes.append(
                f"{event['eventName']} authorizes several permissions; "
                f"{permission.action} is asserted by the mapping, not stated by the event"
            )
        if permission.note:
            notes.append(permission.note)

        resource_arn = _resource_from_event_array(
            event, permission.resource_type, permission.resource_arn_contains
        )
        missing: list[str] = []
        if resource_arn is None and permission.resource is not None:
            if permission.resource_may_be_arn:
                resource_arn = _verbatim_arn(permission.resource, event)
            if resource_arn is None:
                resource_arn, missing = _render_template(permission.resource, event)
            if missing:
                notes.append(
                    "resource ARN not built: event is missing "
                    + ", ".join(sorted(set(missing)))
                )

        if resource_arn is None:
            confidence = Confidence.UNKNOWN_RESOURCE
        elif inferred:
            confidence = Confidence.INFERRED
        else:
            confidence = Confidence.EXACT

        return AuthorizationRequest(
            principal_arn=principal.arn,
            action=permission.action,
            resource_arn=resource_arn,
            context=frozen_context,
            confidence=confidence,
            notes=tuple(notes),
        )

    @staticmethod
    def _build_meta(event: dict[str, Any]) -> EventMeta:
        raw_time = event.get("eventTime") or ""
        try:
            event_time = datetime.fromisoformat(raw_time)
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
        except ValueError:
            event_time = datetime.fromtimestamp(0, tz=timezone.utc)

        return EventMeta(
            event_id=event.get("eventID") or "",
            event_time=event_time,
            event_name=event.get("eventName") or "",
            event_source=event.get("eventSource") or "",
            aws_region=event.get("awsRegion") or "",
            outcome=classify(event),
            error_code=error_code_of(event),
        )
