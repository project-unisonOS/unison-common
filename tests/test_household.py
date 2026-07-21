from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from unison_common.household import (
    AssistantResourceQuota,
    CalendarEventDetails,
    CoordinationAction,
    GroceryItemDetails,
    HouseholdArtifactKind,
    HouseholdCoordinationRequest,
)


def test_calendar_request_requires_matching_typed_payload():
    start = datetime.now(timezone.utc)
    request = HouseholdCoordinationRequest(
        household_id="hh-one",
        space_id="space-shared",
        action=CoordinationAction.CREATE,
        purpose="coordinate dinner",
        artifact_kind=HouseholdArtifactKind.CALENDAR_EVENT,
        calendar=CalendarEventDetails(
            title="Dinner", starts_at=start, ends_at=start + timedelta(hours=1)
        ),
    )
    assert request.calendar.title == "Dinner"


def test_grocery_request_rejects_cross_kind_payload():
    with pytest.raises(ValidationError):
        HouseholdCoordinationRequest(
            household_id="hh-one",
            space_id="space-shared",
            action="create",
            purpose="buy groceries",
            artifact_kind="calendar_event",
            grocery=GroceryItemDetails(item="tea"),
        )


def test_delete_and_list_cannot_smuggle_content():
    with pytest.raises(ValidationError):
        HouseholdCoordinationRequest(
            household_id="hh-one",
            space_id="space-shared",
            action="delete",
            purpose="remove item",
            artifact_id="artifact-one",
            artifact_kind="grocery_item",
            grocery=GroceryItemDetails(item="private title"),
        )


def test_resource_quotas_are_bounded():
    with pytest.raises(ValidationError):
        AssistantResourceQuota(assistant_instance_id="assistant-one", memory_mb=32)

