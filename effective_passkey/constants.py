"""Static reference data: deadlines, privileged roles, method names, known AAGUIDs.

Everything here is data the rules read. Keep it boring and well sourced; when
Microsoft changes a date or adds a role, this is the only file to touch.
"""

from datetime import date

TOOL_NAME = "EffectivePasskey"

# Microsoft-provided SMS and voice authentication retirement (Microsoft Learn).
SMS_RETIREMENT_MAIN = date(2027, 2, 1)
# Global Administrators and external users follow later.
SMS_RETIREMENT_LATE = date(2027, 7, 1)
# Passkeys auto-enabled for SMS/voice users in an "all passkey types" profile.
AUTO_ENABLE_DATE = date(2026, 9, 1)

GLOBAL_ADMIN_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# Directory role template IDs treated as privileged (Tier 0 / Tier 1 admin roles).
PRIVILEGED_ROLE_TEMPLATES = {
    GLOBAL_ADMIN_TEMPLATE_ID: "Global Administrator",
    "e8611ab8-c189-46e8-94e1-60213ab1f814": "Privileged Role Administrator",
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13": "Privileged Authentication Administrator",
    "c4e39bd9-1100-46d3-8c65-fb160da0071f": "Authentication Administrator",
    "194ae4cb-b126-40b2-bd5b-6091b380977d": "Security Administrator",
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9": "Conditional Access Administrator",
    "fe930be7-5e62-47db-91af-98c3a49a38b1": "User Administrator",
    "29232cdf-9323-42fd-ade2-1d097af3e4de": "Exchange Administrator",
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c": "SharePoint Administrator",
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3": "Application Administrator",
    "158c047a-c907-4556-b7ef-446551a6b5f7": "Cloud Application Administrator",
    "3a2c62db-5318-420d-8d74-23affee5d9d5": "Intune Administrator",
    "729827e3-9c14-49f7-bb1b-9608f156bbb8": "Helpdesk Administrator",
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2": "Hybrid Identity Administrator",
    "966707d0-3269-4727-9be2-8c3a10f19b9d": "Password Administrator",
}

# methodsRegistered values from the userRegistrationDetails report.
PHONE_METHODS = {"mobilePhone", "alternateMobilePhone", "officePhone", "sms", "voice"}
# Methods that do not count as an MFA alternative to SMS/voice.
NON_MFA_METHODS = {"email", "securityQuestion", "password", "temporaryAccessPass"}
PHISHING_RESISTANT_METHODS = {
    "passKeyDeviceBound",
    "passKeyDeviceBoundAuthenticator",
    "passKeyDeviceBoundWindowsHello",
    "passKeySynced",
    "fido2SecurityKey",
    "windowsHelloForBusiness",
    "x509Certificate",
    "certificateBasedAuthentication",
    "platformCredential",
}

# A small, extendable map of well-known passkey provider AAGUIDs. Used only to
# classify already-registered keys as synced or device-bound when the export
# does not say so directly. Override or extend with --aaguid-map.
KNOWN_AAGUIDS = {
    "fbfc3007-154e-4ecc-8c0b-6e020557d7bd": ("iCloud Keychain", "synced"),
    "ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4": ("Google Password Manager", "synced"),
    "bada5566-a7aa-401f-bd96-45619a55120d": ("1Password", "synced"),
    "d548826e-79b4-db40-a3d8-11116f7e8349": ("Bitwarden", "synced"),
    "531126d6-e717-415c-9320-3d9aa6981239": ("Dashlane", "synced"),
    "53414d53-554e-4700-0000-000000000000": ("Samsung Pass", "synced"),
    "90a3ccdf-635c-4729-a248-9b709135078f": ("Microsoft Authenticator (iOS)", "deviceBound"),
    "de1e552d-db1d-4423-a619-566b625cdc84": ("Microsoft Authenticator (Android)", "deviceBound"),
    "cb69481e-8ff7-4039-93ec-0a2729a154a8": ("YubiKey 5 (USB-A, FW 5.1)", "deviceBound"),
    "ee882879-721c-4913-9775-3dfcce97072a": ("YubiKey 5 NFC", "deviceBound"),
    "2fc0579f-8113-47ea-b116-bb5a8db9202a": ("YubiKey 5 NFC (FW 5.2/5.4)", "deviceBound"),
    "a4e9fc6d-4cbe-4758-b8ba-37598bb5bbaa": ("YubiKey 5 NFC (FW 5.7)", "deviceBound"),
    "08987058-cadc-4b81-b6e1-30de50dcbe96": ("Windows Hello", "deviceBound"),
}

# Authenticator AAGUIDs that Entra adds to an allow list automatically when
# Microsoft Authenticator passkeys are enabled (R10 hygiene check).
AUTHENTICATOR_AAGUIDS = {
    "90a3ccdf-635c-4729-a248-9b709135078f",
    "de1e552d-db1d-4423-a619-566b625cdc84",
}

# Soft hygiene thresholds (R10). These are configurable defaults, not
# Microsoft-published hard limits.
MAX_PROFILES_SOFT = 3
MAX_AAGUIDS_SOFT = 50

ALL_USERS_TARGET = "all_users"

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
