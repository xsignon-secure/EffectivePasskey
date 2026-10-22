"""Load the four read-only exports and normalize them into plain dataclasses.

The loaders are deliberately tolerant: they accept raw Graph responses
(`{"value": [...]}`), bare lists, and the slightly simplified shapes the
collector script writes. Anything the engine relies on is normalized here so
the resolver and rules never touch raw JSON.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from .constants import (
    ALL_USERS_TARGET,
    GLOBAL_ADMIN_TEMPLATE_ID,
    KNOWN_AAGUIDS,
    PRIVILEGED_ROLE_TEMPLATES,
)

INPUT_FILES = {
    "policy": "policy.json",
    "groups": "groups.json",
    "users": "users.json",
    "roles": "roles.json",
}


class InputError(Exception):
    """Raised when an export is missing or cannot be understood."""


@dataclass
class PasskeyProfile:
    id: str
    name: str
    passkey_types: set[str]  # subset of {"deviceBound", "synced"}
    attestation_enforced: bool
    key_restriction_enforced: bool = False
    key_restriction_type: str = "allow"  # "allow" or "block"
    aaguids: set[str] = field(default_factory=set)
    is_default: bool = False
    synthesized: bool = False  # built from a pre-profile (legacy) FIDO2 config

    def permits(self, passkey_type: str, aaguid: str | None, attested: bool | None) -> bool:
        """True if a credential with these properties satisfies this profile."""
        if passkey_type not in self.passkey_types:
            return False
        if self.attestation_enforced:
            # Attestation is impossible for synced passkeys.
            if passkey_type == "synced" or attested is False:
                return False
        if self.key_restriction_enforced:
            listed = (aaguid or "").lower() in self.aaguids
            if self.key_restriction_type == "allow" and not listed:
                return False
            if self.key_restriction_type == "block" and listed:
                return False
        return True


@dataclass
class Target:
    id: str
    target_type: str = "group"
    profile_ids: list[str] = field(default_factory=list)


@dataclass
class Fido2Policy:
    state: str
    profiles: dict[str, PasskeyProfile]
    include_targets: list[Target]
    exclude_targets: list[Target]
    legacy: bool = False

    @property
    def enabled(self) -> bool:
        return self.state.lower() == "enabled"

    @property
    def default_profile_id(self) -> str | None:
        for p in self.profiles.values():
            if p.is_default:
                return p.id
        return next(iter(self.profiles), None)


@dataclass
class Campaign:
    state: str = "disabled"
    snooze_days: int | None = None
    enforce_after_snoozes: bool | None = None
    include_targets: list[Target] = field(default_factory=list)
    exclude_targets: list[Target] = field(default_factory=list)
    targeted_method: str | None = None
    present: bool = False


@dataclass
class Fido2Key:
    id: str
    display_name: str
    aaguid: str
    passkey_type: str  # "synced", "deviceBound" or "unknown"
    attested: bool | None
    model: str = ""
    created: str = ""


@dataclass
class User:
    id: str
    upn: str
    display_name: str
    user_type: str = "member"
    category: str = "member"  # "member", "internalGuest", "external"
    methods: set[str] = field(default_factory=set)
    roles: list[dict] = field(default_factory=list)  # {"name", "templateId", "assignment"}
    keys: list[Fido2Key] = field(default_factory=list)
    keys_known: bool = False  # True if per-user FIDO2 detail was exported

    @property
    def is_privileged(self) -> bool:
        return bool(self.roles)

    @property
    def is_global_admin(self) -> bool:
        return any(r["templateId"] == GLOBAL_ADMIN_TEMPLATE_ID for r in self.roles)

    @property
    def label(self) -> str:
        return self.upn or self.display_name or self.id


@dataclass
class Group:
    id: str
    name: str
    members: list[str]


@dataclass
class Tenant:
    name: str
    fido2: Fido2Policy
    campaign: Campaign
    phone_methods_enabled: bool
    groups: dict[str, Group]
    users: dict[str, User]
    source_dir: str = ""
    raw_policy: dict = field(default_factory=dict)

    def group_name(self, gid: str) -> str:
        if gid == ALL_USERS_TARGET:
            return "All users"
        g = self.groups.get(gid)
        return g.name if g else gid


# ---------------------------------------------------------------- helpers


def _read_json(path: str):
    try:
        with open(path, encoding="utf-8-sig") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise InputError(f"missing export: {path}") from None
    except json.JSONDecodeError as exc:
        raise InputError(f"{path} is not valid JSON: {exc}") from None


def _unwrap(data, *keys):
    """Return a list from a Graph-style response or one of the named keys."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in keys + ("value",):
            if k in data and isinstance(data[k], list):
                return data[k]
    return []


def _types(raw) -> set[str]:
    if raw is None:
        return {"deviceBound", "synced"}
    if isinstance(raw, str):
        raw = raw.split(",")
    out = set()
    for t in raw:
        t = str(t).strip()
        low = t.lower()
        if low in ("devicebound", "device-bound", "device_bound"):
            out.add("deviceBound")
        elif low == "synced":
            out.add("synced")
        elif low in ("all", "any"):
            out.update({"deviceBound", "synced"})
    return out


def _targets(raw) -> list[Target]:
    out = []
    for t in raw or []:
        pids = t.get("passkeyProfileIds") or t.get("passkeyProfiles") or []
        if isinstance(pids, str):
            pids = [pids]
        out.append(
            Target(
                id=str(t.get("id", "")),
                target_type=str(t.get("targetType", "group")),
                profile_ids=[str(p) for p in pids],
            )
        )
    return out


def _attestation(raw: dict) -> bool:
    val = raw.get("attestationEnforcement")
    if val is None:
        return bool(raw.get("isAttestationEnforced", False))
    return str(val).lower() not in ("disabled", "none", "false", "")


def _key_restrictions(raw: dict):
    kr = raw.get("keyRestrictions") or {}
    return (
        bool(kr.get("isEnforced", False)),
        str(kr.get("enforcementType", "allow")).lower(),
        {a.lower() for a in kr.get("aaGuids", []) or []},
    )


def _profile(raw: dict) -> PasskeyProfile:
    enforced, ktype, aaguids = _key_restrictions(raw)
    pid = str(raw.get("id") or raw.get("displayName") or "profile")
    name = str(raw.get("displayName") or raw.get("name") or pid)
    return PasskeyProfile(
        id=pid,
        name=name,
        passkey_types=_types(raw.get("passkeyTypes")),
        attestation_enforced=_attestation(raw),
        key_restriction_enforced=enforced,
        key_restriction_type=ktype,
        aaguids=aaguids,
        is_default=bool(raw.get("isDefault")) or name.lower() == "default",
    )


def _method_configs(policy: dict) -> list[dict]:
    return _unwrap(policy, "authenticationMethodConfigurations")


def _config_type(cfg: dict) -> str:
    return (cfg.get("@odata.type", "") + " " + str(cfg.get("id", ""))).lower()


def parse_fido2(policy: dict) -> Fido2Policy:
    fido = None
    for cfg in _method_configs(policy):
        if "fido2" in _config_type(cfg):
            fido = cfg
            break
    if fido is None:
        raise InputError("policy.json has no FIDO2 (passkey) method configuration")

    raw_profiles = fido.get("passkeyProfiles")
    legacy = not raw_profiles
    if legacy:
        # Pre-profile tenants: mirror Microsoft's migration, which derived
        # passkeyType from the old attestation toggle (synced enabled wherever
        # attestation enforcement was off).
        attested = _attestation(fido)
        enforced, ktype, aaguids = _key_restrictions(fido)
        profiles = {
            "default": PasskeyProfile(
                id="default",
                name="Default (legacy FIDO2 settings)",
                passkey_types={"deviceBound"} if attested else {"deviceBound", "synced"},
                attestation_enforced=attested,
                key_restriction_enforced=enforced,
                key_restriction_type=ktype,
                aaguids=aaguids,
                is_default=True,
                synthesized=True,
            )
        }
    else:
        profiles = {}
        for rp in raw_profiles:
            p = _profile(rp)
            profiles[p.id] = p

    return Fido2Policy(
        state=str(fido.get("state", "disabled")),
        profiles=profiles,
        include_targets=_targets(fido.get("includeTargets")),
        exclude_targets=_targets(fido.get("excludeTargets")),
        legacy=legacy,
    )


def parse_campaign(policy: dict) -> Campaign:
    reg = (policy.get("registrationEnforcement") or {}) if isinstance(policy, dict) else {}
    raw = reg.get("authenticationMethodsRegistrationCampaign")
    if not raw:
        return Campaign()
    inc = raw.get("includeTargets") or []
    return Campaign(
        state=str(raw.get("state", "disabled")),
        snooze_days=raw.get("snoozeDurationInDays"),
        enforce_after_snoozes=raw.get("enforceRegistrationAfterAllowedSnoozes"),
        include_targets=_targets(inc),
        exclude_targets=_targets(raw.get("excludeTargets")),
        targeted_method=(inc[0].get("targetedAuthenticationMethod") if inc else None),
        present=True,
    )


def parse_phone_enabled(policy: dict) -> bool:
    for cfg in _method_configs(policy):
        t = _config_type(cfg)
        if ("sms" in t or "voice" in t) and str(cfg.get("state", "")).lower() == "enabled":
            return True
    return False


def parse_groups(data) -> dict[str, Group]:
    groups = {}
    for g in _unwrap(data, "groups"):
        members = []
        for m in g.get("members", []) or []:
            members.append(str(m["id"]) if isinstance(m, dict) else str(m))
        gid = str(g["id"])
        groups[gid] = Group(id=gid, name=str(g.get("displayName", gid)), members=members)
    return groups


def _category(raw: dict) -> str:
    explicit = raw.get("identityCategory")
    if explicit in ("member", "internalGuest", "external"):
        return explicit
    utype = str(raw.get("userType", "member")).lower()
    upn = str(raw.get("userPrincipalName", ""))
    if "#ext#" in upn.lower() or str(raw.get("creationType", "")).lower() == "invitation":
        return "external"
    if utype == "guest":
        return "internalGuest"
    return "member"


def parse_users(data) -> dict[str, User]:
    users = {}
    for u in _unwrap(data, "users", "userRegistrationDetails"):
        uid = str(u["id"])
        users[uid] = User(
            id=uid,
            upn=str(u.get("userPrincipalName", "")),
            display_name=str(u.get("userDisplayName") or u.get("displayName") or ""),
            user_type=str(u.get("userType", "member")),
            category=_category(u),
            methods={str(m) for m in u.get("methodsRegistered", []) or []},
        )
    return users


def _key(raw: dict, aaguid_map: dict) -> Fido2Key:
    aaguid = str(raw.get("aaGuid") or raw.get("aaguid") or "").lower()
    known = aaguid_map.get(aaguid)
    ptype = raw.get("passkeyType")
    if ptype:
        ptype = "synced" if "sync" in str(ptype).lower() else "deviceBound"
    elif known:
        ptype = known[1]
    else:
        ptype = "unknown"
    level = raw.get("attestationLevel")
    attested = None if level is None else str(level).lower() == "attested"
    if ptype == "synced":
        attested = False
    return Fido2Key(
        id=str(raw.get("id", "")),
        display_name=str(raw.get("displayName", "")),
        aaguid=aaguid,
        passkey_type=ptype,
        attested=attested,
        model=str(raw.get("model") or (known[0] if known else "")),
        created=str(raw.get("createdDateTime", "")),
    )


def _expand_principal(pid: str, groups: dict[str, Group], seen=None) -> set[str]:
    """Expand a group principal into user ids; a user id returns itself."""
    if pid not in groups:
        return {pid}
    seen = seen or set()
    if pid in seen:
        return set()
    seen.add(pid)
    out = set()
    for m in groups[pid].members:
        out |= _expand_principal(m, groups, seen)
    return out


def apply_roles(data, users: dict[str, User], groups: dict[str, Group], aaguid_map: dict):
    for ra in _unwrap(data, "roleAssignments"):
        tid = str(ra.get("roleTemplateId") or ra.get("roleDefinitionId") or "").lower()
        name = PRIVILEGED_ROLE_TEMPLATES.get(tid) or ra.get("roleDisplayName")
        if tid not in PRIVILEGED_ROLE_TEMPLATES and not ra.get("privileged"):
            continue
        pid = str(ra.get("principalId", ""))
        for uid in _expand_principal(pid, groups):
            if uid in users:
                users[uid].roles.append(
                    {
                        "name": name,
                        "templateId": tid,
                        "assignment": str(ra.get("assignmentType", "active")),
                        "via": groups[pid].name if pid in groups else None,
                    }
                )

    fido = data.get("fido2Methods", {}) if isinstance(data, dict) else {}
    if isinstance(fido, list):
        fido = {str(e.get("userId")): e.get("methods", []) for e in fido}
    for uid, methods in fido.items():
        if uid in users:
            users[uid].keys = [_key(m, aaguid_map) for m in methods or []]
            users[uid].keys_known = True


def load_aaguid_map(path: str | None) -> dict:
    amap = dict(KNOWN_AAGUIDS)
    if path:
        extra = _read_json(path)
        for k, v in extra.items():
            if isinstance(v, dict):
                amap[k.lower()] = (v.get("name", k), v.get("type", "unknown"))
            else:
                amap[k.lower()] = tuple(v)
    return amap


def load_tenant(directory: str, name: str | None = None, aaguid_map_path: str | None = None) -> Tenant:
    """Load a directory holding policy.json, groups.json, users.json, roles.json."""
    if not os.path.isdir(directory):
        raise InputError(f"input directory not found: {directory}")
    paths = {k: os.path.join(directory, v) for k, v in INPUT_FILES.items()}
    policy = _read_json(paths["policy"])
    groups = parse_groups(_read_json(paths["groups"]))
    users = parse_users(_read_json(paths["users"]))
    roles_data = _read_json(paths["roles"])
    apply_roles(roles_data, users, groups, load_aaguid_map(aaguid_map_path))

    tenant_name = name
    if not tenant_name and isinstance(policy, dict):
        tenant_name = policy.get("tenantDisplayName")
    return Tenant(
        name=tenant_name or os.path.basename(os.path.abspath(directory)),
        fido2=parse_fido2(policy),
        campaign=parse_campaign(policy),
        phone_methods_enabled=parse_phone_enabled(policy),
        groups=groups,
        users=users,
        source_dir=directory,
        raw_policy=policy if isinstance(policy, dict) else {"value": policy},
    )
