from uuid import uuid4

from alaira_warden.identity.dispatch import authorize_model_dispatch, model_dispatch_allowed
from tests.identity.conftest import principal_with

APP_A = uuid4()
APP_B = uuid4()
DESTINATION = "approved-model"
APPROVED = frozenset({DESTINATION})
FIELDS = ("case_id", "package_names", "versions")


def _dispatch(principal, application_id, **overrides):
    payload = {
        "policy": "allow_minimized",
        "destination": DESTINATION,
        "approved_destinations": APPROVED,
        "fields": FIELDS,
    }
    payload.update(overrides)
    return authorize_model_dispatch(principal, application_id, **payload)


def test_model_dispatch_denies_by_default_even_for_platform_admin():
    admin = principal_with("administrador", None)
    decision = authorize_model_dispatch(
        admin,
        APP_A,
        destination=DESTINATION,
        approved_destinations=APPROVED,
        fields=FIELDS,
    )
    assert decision.allowed is False
    assert decision.reason == "policy_denied"
    assert decision.permitted_fields == ()
    assert model_dispatch_allowed(admin, APP_A, destination=DESTINATION) is False


def test_model_dispatch_requires_scope_destination_and_minimized_fields():
    analyst = principal_with("analista", APP_A)
    allowed = _dispatch(analyst, APP_A)
    assert allowed.allowed is True
    assert allowed.permitted_fields == FIELDS

    other = _dispatch(analyst, APP_B)
    assert other.allowed is False
    assert other.permitted_fields == ()

    denied_policy = _dispatch(analyst, APP_A, policy="deny")
    assert denied_policy.allowed is False
    unknown = _dispatch(analyst, APP_A, destination="other-model")
    assert unknown.allowed is False
    empty_catalog = _dispatch(analyst, APP_A, approved_destinations=frozenset())
    assert empty_catalog.allowed is False
    no_fields = _dispatch(analyst, APP_A, fields=())
    assert no_fields.allowed is False
    code = _dispatch(analyst, APP_A, fields=("case_id", "source_code"))
    assert code.allowed is False
    assert code.permitted_fields == ()

    auditor = principal_with("auditor", APP_A)
    assert _dispatch(auditor, APP_A).allowed is True
    developer = principal_with("desarrollador", APP_A)
    assert _dispatch(developer, APP_A).allowed is True
    assert (
        model_dispatch_allowed(
            "not-a-principal",
            APP_A,
            policy="allow_minimized",
            destination=DESTINATION,
            approved_destinations=APPROVED,
            fields=FIELDS,
        )
        is False
    )
