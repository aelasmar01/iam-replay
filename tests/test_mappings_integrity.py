"""Structural invariants every mapping file must hold.

These run over whatever mappings exist, so services added in later milestones
inherit the checks without anyone remembering to extend this file.
"""

from __future__ import annotations

import pytest
import yaml

from iam_replay.normalize.mapper import MAPPINGS_DIR, SERVICE_ALLOWLIST

MAPPING_FILES = sorted(MAPPINGS_DIR.glob("*.yaml"))


def documents():
    for path in MAPPING_FILES:
        yield path, yaml.safe_load(path.read_text())


def permission_entries():
    """(path, event_name, entry) for every declared permission."""
    for path, document in documents():
        for event_name, spec in (document.get("events") or {}).items():
            if spec.get("requires_no_authorization"):
                continue
            entries = spec.get("expands_to") or [spec]
            for entry in entries:
                yield path, event_name, entry


def test_there_are_mapping_files_to_check():
    assert MAPPING_FILES


@pytest.mark.parametrize("path", MAPPING_FILES, ids=lambda p: p.name)
def test_service_key_matches_the_filename_and_the_allowlist(path):
    document = yaml.safe_load(path.read_text())
    assert document["service"] == path.stem
    assert document["service"] in SERVICE_ALLOWLIST


#: The one action a mapping may declare outside its own service. iam:PassRole
#: is never logged as an event of its own, so events that require it (
#: lambda:CreateFunction, ec2:RunInstances with an instance profile) assert it
#: through an expansion. Spec §6 calls for exactly this and no more: no general
#: PassRole detection is attempted.
CROSS_SERVICE_ACTIONS = {"iam:PassRole"}


def test_actions_are_prefixed_with_their_own_service():
    """An action under the wrong service prefix silently never matches a policy
    written for that service, producing a false DENY."""
    for path, event_name, entry in permission_entries():
        service = path.stem
        action = entry["action"]
        assert ":" in action, f"{path.name}:{event_name} action {action!r} has no prefix"
        if action in CROSS_SERVICE_ACTIONS:
            continue
        assert action.split(":", 1)[0] == service, (
            f"{path.name}:{event_name} declares {action!r} under service {service!r}"
        )


def test_cross_service_actions_only_appear_inside_expansions():
    """iam:PassRole is an assertion by the mapping, never something the event
    states, so it must always carry the INFERRED marking an expansion gives it."""
    for path, document in documents():
        for event_name, spec in (document.get("events") or {}).items():
            action = spec.get("action")
            if action in CROSS_SERVICE_ACTIONS:
                raise AssertionError(
                    f"{path.name}:{event_name} declares {action} directly; it must "
                    "sit inside expands_to so every entry is marked INFERRED"
                )


def test_no_resource_template_is_a_bare_wildcard_with_placeholders():
    """'*' is legitimate for account-wide actions, and a template is legitimate.
    A template that mixes the two -- 'arn:...{field}*' collapsing to a wildcard
    when the field is missing -- is not: the mapper would widen instead of
    reporting UNKNOWN_RESOURCE."""
    for path, event_name, entry in permission_entries():
        resource = entry.get("resource")
        if resource is None or resource == "*":
            continue
        assert "{" in resource, (
            f"{path.name}:{event_name} has a literal resource {resource!r}; "
            "either use a template or declare '*' explicitly"
        )


def test_every_event_declares_something():
    for path, document in documents():
        for event_name, spec in (document.get("events") or {}).items():
            has_action = "action" in spec
            has_expansion = "expands_to" in spec
            no_authz = bool(spec.get("requires_no_authorization"))
            assert sum((has_action, has_expansion, no_authz)) == 1, (
                f"{path.name}:{event_name} must declare exactly one of "
                "action, expands_to, or requires_no_authorization"
            )


def test_expansions_declare_more_than_one_permission_or_explain_themselves():
    """expands_to marks everything it produces INFERRED. Using it for a single
    ordinary permission would understate confidence for no reason."""
    for path, document in documents():
        for event_name, spec in (document.get("events") or {}).items():
            if "expands_to" not in spec:
                continue
            entries = spec["expands_to"] or []
            assert entries, f"{path.name}:{event_name} has an empty expands_to"
            if len(entries) == 1:
                assert entries[0].get("note"), (
                    f"{path.name}:{event_name} expands to one permission without "
                    "a note explaining why it is inferred"
                )


def test_mapping_files_load_through_the_mapper(mapper):
    """Parse errors must surface here, not at replay time."""
    assert mapper.supported_services
    assert mapper.supported_services <= SERVICE_ALLOWLIST
