# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Keycloak sign-in lands users in the platform workspace.

Membership follows the identity provider: the realm's `groups` claim decides
the role, roles only move up, and nothing happens when the feature is off.
"""

from unittest.mock import patch

import pytest

from plane.authentication.utils.keycloak_workspace import (
    ROLE_ADMIN,
    ROLE_GUEST,
    ROLE_MEMBER,
    auto_join_workspace,
    normalise_groups,
    role_for_groups,
)
from plane.db.models import User, Workspace, WorkspaceMember


def _configured(slug="adhar", admin="platform-admin", guest="platform-viewer"):
    return patch(
        "plane.authentication.utils.keycloak_workspace.get_configuration_value",
        return_value=(slug, admin, guest),
    )


@pytest.mark.unit
class TestGroupMapping:
    def test_full_path_and_bare_names_normalise_to_the_leaf(self):
        assert normalise_groups(["/platform-admin", "developers", "/org/platform-viewer", 3, ""]) == {
            "platform-admin",
            "developers",
            "platform-viewer",
        }

    def test_non_list_claim_is_empty(self):
        assert normalise_groups("platform-admin") == set()
        assert normalise_groups(None) == set()

    @pytest.mark.parametrize(
        "groups,expected",
        [
            ({"platform-admin"}, ROLE_ADMIN),
            ({"platform-admin", "platform-viewer"}, ROLE_ADMIN),
            ({"platform-viewer"}, ROLE_GUEST),
            ({"platform-developer"}, ROLE_MEMBER),
            (set(), ROLE_MEMBER),
        ],
    )
    def test_role_precedence(self, groups, expected):
        assert role_for_groups(groups, {"platform-admin"}, {"platform-viewer"}) == expected


@pytest.mark.unit
@pytest.mark.django_db
class TestAutoJoin:
    @pytest.fixture
    def owner(self):
        return User.objects.create(email="owner@example.com", username="owner")

    @pytest.fixture
    def workspace(self, owner):
        ws = Workspace.objects.create(name="Adhar", slug="adhar", owner=owner)
        WorkspaceMember.objects.create(workspace=ws, member=owner, role=ROLE_ADMIN)
        return ws

    @pytest.fixture
    def person(self):
        return User.objects.create(email="person@example.com", username="person")

    def test_off_when_unconfigured(self, workspace, person):
        with _configured(slug=""):
            assert auto_join_workspace(person, ["platform-admin"]) is None
        assert not WorkspaceMember.objects.filter(member=person).exists()

    def test_unknown_slug_is_a_noop(self, workspace, person):
        with _configured(slug="nope"):
            assert auto_join_workspace(person, []) is None
        assert not WorkspaceMember.objects.filter(member=person).exists()

    def test_new_user_joins_as_member_by_default(self, workspace, person):
        with _configured():
            member = auto_join_workspace(person, ["/platform-developer"])
        assert member.workspace == workspace and member.role == ROLE_MEMBER and member.is_active

    def test_admin_group_joins_as_admin(self, workspace, person):
        with _configured():
            assert auto_join_workspace(person, ["/platform-admin"]).role == ROLE_ADMIN

    def test_guest_group_joins_as_guest(self, workspace, person):
        with _configured():
            assert auto_join_workspace(person, ["platform-viewer"]).role == ROLE_GUEST

    def test_roles_move_up_but_never_down(self, workspace, person):
        with _configured():
            auto_join_workspace(person, ["platform-viewer"])
            assert auto_join_workspace(person, ["platform-admin"]).role == ROLE_ADMIN
            # Leaving the admin group does not demote: that is a deliberate act.
            assert auto_join_workspace(person, []).role == ROLE_ADMIN
        assert WorkspaceMember.objects.filter(member=person, workspace=workspace).count() == 1

    def test_deactivated_membership_is_reactivated(self, workspace, person):
        WorkspaceMember.objects.create(workspace=workspace, member=person, role=ROLE_MEMBER, is_active=False)
        with _configured():
            member = auto_join_workspace(person, [])
        assert member.is_active is True

    def test_custom_group_names_are_honoured(self, workspace, person):
        with _configured(admin="plane-admins, owners", guest="readers"):
            assert auto_join_workspace(person, ["owners"]).role == ROLE_ADMIN
