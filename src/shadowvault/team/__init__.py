"""Team mode with role-based access control."""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from ..vault.schema import TeamMember, TeamRole


class TeamError(Exception):
    """Base exception for team operations."""


class PermissionDeniedError(TeamError):
    """Raised when a user lacks required permissions."""


PermissionDenied = PermissionDeniedError


class MemberNotFoundError(TeamError):
    """Raised when a team member is not found."""


class TeamManager:
    """Manage team members and RBAC."""

    # Permission matrix
    PERMISSIONS = {
        TeamRole.OWNER: {
            "read",
            "write",
            "delete",
            "export",
            "manage_members",
            "view_audit",
            "manage_vault",
        },
        TeamRole.ANNOTATOR: {
            "read",
            "write",
            "annotate",
        },
        TeamRole.VIEWER: {
            "read",
        },
    }

    def __init__(self, owner_id: str = "local"):
        """Initialize team manager.

        Args:
            owner_id: ID of the vault owner.
        """
        self._members: dict[str, TeamMember] = {}
        self._owner_id = owner_id

        # Add owner
        self._members[owner_id] = TeamMember(
            user_id=owner_id,
            email="",
            role=TeamRole.OWNER,
            added_at=datetime.now(timezone.utc),
            added_by="system",
            active=True,
        )

    def add_member(
        self,
        user_id: str,
        email: str = "",
        role: TeamRole = TeamRole.VIEWER,
        added_by: str = "local",
    ) -> TeamMember:
        """Add a team member.

        Args:
            user_id: Unique user identifier.
            email: User email.
            role: User role.
            added_by: Who added this member.

        Returns:
            The created TeamMember.

        Raises:
            TeamError: If user already exists.
        """
        if user_id in self._members:
            raise TeamError(f"User {user_id} already exists")

        member = TeamMember(
            user_id=user_id,
            email=email,
            role=role,
            added_at=datetime.now(timezone.utc),
            added_by=added_by,
            active=True,
        )
        self._members[user_id] = member
        return member

    def remove_member(self, user_id: str) -> bool:
        """Remove a team member.

        Args:
            user_id: User ID to remove.

        Returns:
            True if removed, False if not found.

        Raises:
            TeamError: If trying to remove the owner.
        """
        if user_id == self._owner_id:
            raise TeamError("Cannot remove the owner")

        if user_id in self._members:
            del self._members[user_id]
            return True
        return False

    def update_role(self, user_id: str, new_role: TeamRole) -> TeamMember:
        """Update a member's role.

        Args:
            user_id: User ID.
            new_role: New role.

        Returns:
            Updated TeamMember.

        Raises:
            MemberNotFoundError: If user not found.
            TeamError: If trying to change owner's role.
        """
        if user_id == self._owner_id:
            raise TeamError("Cannot change owner's role")

        if user_id not in self._members:
            raise MemberNotFoundError(f"User {user_id} not found")

        self._members[user_id].role = new_role
        return self._members[user_id]

    def deactivate_member(self, user_id: str) -> bool:
        """Deactivate a team member.

        Args:
            user_id: User ID.

        Returns:
            True if deactivated, False if not found.
        """
        if user_id in self._members:
            self._members[user_id].active = False
            return True
        return False

    def activate_member(self, user_id: str) -> bool:
        """Activate a team member.

        Args:
            user_id: User ID.

        Returns:
            True if activated, False if not found.
        """
        if user_id in self._members:
            self._members[user_id].active = True
            return True
        return False

    def get_member(self, user_id: str) -> TeamMember | None:
        """Get a team member.

        Args:
            user_id: User ID.

        Returns:
            TeamMember or None.
        """
        return self._members.get(user_id)

    def list_members(
        self,
        role: TeamRole | None = None,
        active_only: bool = True,
    ) -> list[TeamMember]:
        """List team members.

        Args:
            role: Filter by role.
            active_only: Only return active members.

        Returns:
            List of TeamMember objects.
        """
        members = list(self._members.values())

        if role:
            members = [m for m in members if m.role == role]

        if active_only:
            members = [m for m in members if m.active]

        return members

    def check_permission(self, user_id: str, permission: str) -> bool:
        """Check if a user has a specific permission.

        Args:
            user_id: User ID.
            permission: Permission name.

        Returns:
            True if user has permission.
        """
        member = self._members.get(user_id)
        if not member or not member.active:
            return False

        perms = self.PERMISSIONS.get(member.role, set())
        return permission in perms

    def require_permission(self, user_id: str, permission: str) -> None:
        """Require a user to have a specific permission.

        Args:
            user_id: User ID.
            permission: Required permission.

        Raises:
            PermissionDenied: If user lacks permission.
        """
        if not self.check_permission(user_id, permission):
            raise PermissionDenied(
                f"User {user_id} lacks required permission: {permission}"
            )

    def generate_invitation(self, user_id: str) -> str:
        """Generate an invitation token for a user.

        Args:
            user_id: User ID to invite.

        Returns:
            Invitation token.
        """
        token = secrets.token_urlsafe(32)
        # In a real implementation, this would be stored with expiry
        return f"{user_id}:{token}"

    def to_dict(self) -> list[dict]:
        """Serialize team members to list of dicts."""
        return [m.to_dict() for m in self._members.values()]

    @classmethod
    def from_dict(cls, data: list[dict], owner_id: str = "local") -> TeamManager:
        """Deserialize team members from list of dicts."""
        manager = cls(owner_id=owner_id)
        manager._members.clear()

        for member_data in data:
            member = TeamMember.from_dict(member_data)
            manager._members[member.user_id] = member

            # Set owner if found
            if member.role == TeamRole.OWNER:
                manager._owner_id = member.user_id

        return manager

    @property
    def member_count(self) -> int:
        """Get number of active members."""
        return len([m for m in self._members.values() if m.active])

    @property
    def owner_id(self) -> str:
        """Get owner user ID."""
        return self._owner_id
