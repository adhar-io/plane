# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

"""Land Keycloak users in the platform workspace on sign-in.

Single sign-on that drops a new user on "create your workspace" is only half
done: on a platform install there is exactly one workspace everyone belongs to,
and membership should follow the identity provider rather than an invitation
somebody has to remember to send. When `KEYCLOAK_AUTO_JOIN_WORKSPACE` names a
workspace slug, every successful Keycloak login makes the user a member of it,
with the role derived from the realm's `groups` claim:

    group in KEYCLOAK_ADMIN_GROUPS  -> Admin  (20)
    group in KEYCLOAK_GUEST_GROUPS  -> Guest  (5)
    anything else                   -> Member (15)

Roles only ever move up on login (a guest who joins the admin group becomes an
admin; an admin who leaves it keeps the role) — demotion is a deliberate act
for a workspace admin, not a side effect of a group edit nobody reviewed.
Deactivated memberships are reactivated, since the realm just vouched for the
person. Nothing happens when the slug is unset or names no workspace.
"""

import logging
import os

from plane.db.models import Workspace, WorkspaceMember
from plane.license.utils.instance_value import get_configuration_value
from plane.utils.cache import invalidate_cache_directly

logger = logging.getLogger("plane.authentication")

ROLE_ADMIN = 20
ROLE_MEMBER = 15
ROLE_GUEST = 5

# The platform realm's groups. Overridable per instance; these are the names
# the Adhar platform provisions, so a default install maps without configuration.
DEFAULT_ADMIN_GROUPS = "platform-admin"
DEFAULT_GUEST_GROUPS = "platform-viewer"


def _split_groups(value):
    return {g.strip().strip("/") for g in (value or "").split(",") if g.strip()}


def normalise_groups(claim):
    """Keycloak's group mapper emits either `["admin"]` or `["/admin"]`
    (full path on); the leading slash and any parent path are not part of the
    name an operator configures, so compare on the last path segment."""
    if not isinstance(claim, (list, tuple, set)):
        return set()
    out = set()
    for g in claim:
        if not isinstance(g, str):
            continue
        name = g.strip().strip("/").rsplit("/", 1)[-1]
        if name:
            out.add(name)
    return out


def role_for_groups(groups, admin_groups, guest_groups):
    groups = set(groups)
    if groups & admin_groups:
        return ROLE_ADMIN
    if groups & guest_groups:
        return ROLE_GUEST
    return ROLE_MEMBER


def auto_join_workspace(user, groups):
    """Ensure `user` is a member of the configured workspace; return the
    WorkspaceMember or None when auto-join is off or the slug is unknown."""
    slug, admin_groups, guest_groups = get_configuration_value(
        [
            {
                "key": "KEYCLOAK_AUTO_JOIN_WORKSPACE",
                "default": os.environ.get("KEYCLOAK_AUTO_JOIN_WORKSPACE", ""),
            },
            {
                "key": "KEYCLOAK_ADMIN_GROUPS",
                "default": os.environ.get("KEYCLOAK_ADMIN_GROUPS", DEFAULT_ADMIN_GROUPS),
            },
            {
                "key": "KEYCLOAK_GUEST_GROUPS",
                "default": os.environ.get("KEYCLOAK_GUEST_GROUPS", DEFAULT_GUEST_GROUPS),
            },
        ]
    )
    slug = (slug or "").strip()
    if not slug:
        return None

    workspace = Workspace.objects.filter(slug=slug).first()
    if workspace is None:
        logger.warning("KEYCLOAK_AUTO_JOIN_WORKSPACE names unknown workspace %r; skipping", slug)
        return None

    role = role_for_groups(
        normalise_groups(groups),
        _split_groups(admin_groups) or {DEFAULT_ADMIN_GROUPS},
        _split_groups(guest_groups) or {DEFAULT_GUEST_GROUPS},
    )

    member = WorkspaceMember.objects.filter(workspace=workspace, member=user).first()
    changed = False
    if member is None:
        member = WorkspaceMember.objects.create(workspace=workspace, member=user, role=role, is_active=True)
        changed = True
        logger.info("keycloak auto-join: %s added to %s as %s", user.email, slug, role)
    else:
        if not member.is_active:
            member.is_active = True
            changed = True
        if role > member.role:
            member.role = role
            changed = True
        if changed:
            member.save(update_fields=["is_active", "role"])
            logger.info("keycloak auto-join: %s updated in %s (role %s)", user.email, slug, member.role)

    if changed:
        invalidate_cache_directly(
            path=f"/api/workspaces/{slug}/members/",
            url_params=False,
            user=False,
            multiple=True,
        )
    return member
