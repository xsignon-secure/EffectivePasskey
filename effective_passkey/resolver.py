"""Effective passkey policy resolution.

Microsoft's rule (Learn, "passkey profiles"): when a user is scoped for more
than one passkey profile, a passkey is allowed if it fully satisfies the
requirements of *at least one* scoped profile. There is no order and no
"most restrictive wins". Exclusion from the FIDO2 policy blocks entirely and
beats every inclusion.

So the effective policy for a user is the union of their scoped profiles, and
the weakest credential they can register is the weakest credential any one of
those profiles allows.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from .constants import ALL_USERS_TARGET
from .model import PasskeyProfile, Target, Tenant, User

# Weakest-registrable-credential ladder. Higher is weaker.
RANK_LABELS = {
    0: "No passkey can be registered",
    1: "Device-bound, attested, allow-listed authenticators only",
    2: "Device-bound, attested, any authenticator",
    3: "Device-bound, unattested (authenticator model not verified)",
    4: "Synced passkey, allow-listed providers only",
    5: "Synced passkey, any provider, unattested",
}

STATUS_LABELS = {
    "allowed": "Can register passkeys",
    "excluded": "Excluded from passkey policy",
    "disabled": "Passkeys disabled tenant-wide",
    "not_targeted": "Not targeted by passkey policy",
}


def profile_rank(p: PasskeyProfile) -> int:
    """Weakest credential a single profile accepts, on the RANK_LABELS ladder."""
    synced_ok = "synced" in p.passkey_types and not p.attestation_enforced
    if synced_ok:
        restricted = p.key_restriction_enforced and p.key_restriction_type == "allow"
        return 4 if restricted else 5
    if "deviceBound" in p.passkey_types:
        if not p.attestation_enforced:
            # AAGUIDs are self-reported without attestation, so a key
            # restriction here is advisory, not a control.
            return 3
        if p.key_restriction_enforced and p.key_restriction_type == "allow":
            return 1
        return 2
    return 0


@dataclass
class Membership:
    """How a user lands inside a target: the chain of groups that got them there."""

    target_id: str
    path: list[str]  # group ids from the direct group outward to the target


@dataclass
class ScopedProfile:
    profile: PasskeyProfile
    via: list[Membership]
    rank: int


@dataclass
class EffectivePolicy:
    user: User
    status: str
    profiles: list[ScopedProfile] = field(default_factory=list)
    exclusions: list[Membership] = field(default_factory=list)

    @property
    def rank(self) -> int:
        if self.status != "allowed":
            return 0
        return max((sp.rank for sp in self.profiles), default=0)

    @property
    def strictest_rank(self) -> int:
        ranks = [sp.rank for sp in self.profiles if sp.rank > 0]
        return min(ranks, default=0)

    @property
    def weakest_label(self) -> str:
        if self.status != "allowed":
            return STATUS_LABELS[self.status]
        return RANK_LABELS[self.rank]

    @property
    def synced_allowed(self) -> bool:
        return self.rank >= 4

    @property
    def unattested_allowed(self) -> bool:
        return self.rank >= 3

    def loosest_profiles(self) -> list[ScopedProfile]:
        r = self.rank
        return [sp for sp in self.profiles if sp.rank == r and r > 0]

    def permits(self, passkey_type: str, aaguid: str | None, attested: bool | None) -> list[ScopedProfile]:
        """The scoped profiles that would accept this credential (empty = rejected)."""
        if self.status != "allowed":
            return []
        return [sp for sp in self.profiles if sp.profile.permits(passkey_type, aaguid, attested)]


class Resolver:
    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self._paths = self._index_memberships()

    def _index_memberships(self) -> dict[str, dict[str, list[str]]]:
        """For each user, every group they are in (transitively) with one path."""
        groups = self.tenant.groups
        # parent lookup: member id -> groups that directly contain it
        parents: dict[str, list[str]] = {}
        for g in groups.values():
            for m in g.members:
                parents.setdefault(m, []).append(g.id)

        # Ancestors of each group with the shortest path, computed once per group (BFS),
        # so users sharing groups do not repeat the walk.
        ancestors: dict[str, dict[str, list[str]]] = {}

        def walk(start: str) -> dict[str, list[str]]:
            if start not in ancestors:
                found: dict[str, list[str]] = {}
                frontier = deque([(start, [start])])
                while frontier:
                    gid, path = frontier.popleft()
                    if gid in found:
                        continue
                    found[gid] = path
                    for parent in parents.get(gid, []):
                        if parent not in found:
                            frontier.append((parent, path + [parent]))
                ancestors[start] = found
            return ancestors[start]

        index: dict[str, dict[str, list[str]]] = {}
        for uid in self.tenant.users:
            found = {}
            for direct in parents.get(uid, []):
                for gid, path in walk(direct).items():
                    if gid not in found or len(path) < len(found[gid]):
                        found[gid] = path
            index[uid] = found
        return index

    def membership(self, user: User, target: Target) -> Membership | None:
        if target.id == ALL_USERS_TARGET or target.id.lower() == "all_users":
            return Membership(target_id=ALL_USERS_TARGET, path=[ALL_USERS_TARGET])
        if target.target_type.lower() == "user" or target.id == user.id:
            return Membership(target_id=target.id, path=[]) if target.id == user.id else None
        path = self._paths.get(user.id, {}).get(target.id)
        if path is None:
            return None
        return Membership(target_id=target.id, path=path)

    def resolve(self, user: User) -> EffectivePolicy:
        fido = self.tenant.fido2
        if not fido.enabled:
            return EffectivePolicy(user=user, status="disabled")

        exclusions = [m for t in fido.exclude_targets if (m := self.membership(user, t))]
        if exclusions:
            return EffectivePolicy(user=user, status="excluded", exclusions=exclusions)

        scoped: dict[str, ScopedProfile] = {}
        for t in fido.include_targets:
            m = self.membership(user, t)
            if not m:
                continue
            pids = t.profile_ids or [fido.default_profile_id]
            for pid in pids:
                p = fido.profiles.get(pid)
                if p is None:
                    continue
                if pid not in scoped:
                    scoped[pid] = ScopedProfile(profile=p, via=[], rank=profile_rank(p))
                scoped[pid].via.append(m)

        if not scoped:
            return EffectivePolicy(user=user, status="not_targeted")
        ordered = sorted(scoped.values(), key=lambda sp: (-sp.rank, sp.profile.name))
        return EffectivePolicy(user=user, status="allowed", profiles=ordered)

    def resolve_all(self) -> dict[str, EffectivePolicy]:
        return {uid: self.resolve(u) for uid, u in self.tenant.users.items()}

    def describe_path(self, m: Membership) -> str:
        if m.target_id == ALL_USERS_TARGET:
            return "All users (tenant-wide target)"
        if not m.path:
            return "targeted directly"
        names = [self.tenant.group_name(g) for g in m.path]
        if len(names) == 1:
            return f"member of group '{names[0]}'"
        return "member of " + " → ".join(f"'{n}'" for n in names) + " (nested)"
