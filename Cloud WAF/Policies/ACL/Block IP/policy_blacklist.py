#!/usr/bin/env python3
"""
Blocks or unblocks an IP on Imperva Cloud WAF through the IP blacklist of an ACL policy.

Developed by Novared
Contact: helpdesk@novared.net

Uses the Imperva Policy Management API v2 ("Policy Management API Definition" in the Imperva
API docs). Both actions start with GET /v2/policies/{policyId}?extended=true to check the
policy is an ACL and read the blacklist.

  block    POST /v2/policies/{policyId}  partial update: the IP is APPENDED to the existing list.
  unblock  PUT  /v2/policies/{policyId}  full update: the API has no partial removal, so the whole
                                         policy is resent without the IP. It is then re-read to
                                         confirm the IP is gone and nothing else changed.

Parameters (a command-line argument takes precedence over the environment variable):
  --action      IMPERVA_ACTION       block (default) or unblock
  --api-id      IMPERVA_API_ID
  --api-key     IMPERVA_API_KEY      (prefer the env var: arguments show up in the process list)
  --policy-id   IMPERVA_POLICY_ID
  --ip          IMPERVA_BLOCK_IP     (a single IPv4 or IPv6 address)
  --account-id  IMPERVA_ACCOUNT_ID   (optional: only if the policy belongs to a sub-account)
  --dry-run                          (only reads the policy and shows what would be sent)

Output: a single JSON line on stdout. "status" field:
  block:   added | already_blocked | dry_run -> exit 0
  unblock: removed | not_blocked | dry_run   -> exit 0
  error (API or policy state)                -> exit 1
  error (missing/invalid parameter)          -> exit 2

Usage as a module (e.g. a SOAR Python integration):
  from policy_blacklist import block_ip, unblock_ip
  result = block_ip(api_id, api_key, policy_id, ip, account_id=None)
  result = unblock_ip(api_id, api_key, policy_id, ip, account_id=None)
"""
import argparse
import ipaddress
import json
import os
import sys

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

__author__ = "Novared"
__email__ = "helpdesk@novared.net"

API_URL = "https://api.imperva.com/policies/v2/policies/{policy_id}"
TIMEOUT = 30  # seconds

# PolicyDto fields sent back on a full PUT (read-only ones like id/lastModified are left out).
PUT_FIELDS = ("name", "description", "enabled", "policyType", "accountId",
              "policySettings", "defaultPolicyConfig")

PARAMS = (  # (attribute, flag, environment variable, required)
    ("api_id", "--api-id", "IMPERVA_API_ID", True),
    ("api_key", "--api-key", "IMPERVA_API_KEY", True),
    ("policy_id", "--policy-id", "IMPERVA_POLICY_ID", True),
    ("ip", "--ip", "IMPERVA_BLOCK_IP", True),
    ("account_id", "--account-id", "IMPERVA_ACCOUNT_ID", False),
)


class ImpervaError(Exception):
    """Error returned by the API or unexpected policy state."""


def _session(api_id, api_key):
    session = requests.Session()
    session.headers.update({
        "accept": "application/json",
        "x-API-Id": str(api_id),
        "x-API-Key": str(api_key),
    })
    # Transient errors (429/5xx) are retried for idempotent methods (GET/PUT).
    # POST appends data, so it is never retried automatically.
    retry = Retry(total=3, backoff_factor=2, status_forcelist=(429, 500, 502, 503, 504),
                  raise_on_status=False)
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session


def _call(session, method, policy_id, account_id, params=None, payload=None):
    params = dict(params or {})
    if account_id is not None:
        params["caid"] = account_id
    try:
        resp = session.request(method, API_URL.format(policy_id=policy_id), params=params,
                               json=payload, timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise ImpervaError(f"{method} failed to connect to the API: {exc}") from exc
    try:
        body = resp.json()
    except ValueError:
        body = None
    if not resp.ok or not isinstance(body, dict) or body.get("isError"):
        detail = (body.get("value") or body) if isinstance(body, dict) else resp.text[:500]
        raise ImpervaError(f"{method} on policy {policy_id} returned HTTP {resp.status_code}: {detail}")
    return body.get("value")


def _get_policy(session, policy_id, account_id):
    value = _call(session, "GET", policy_id, account_id, params={"extended": "true"})
    if isinstance(value, list) and len(value) == 1:  # the API spec describes "value" as a list
        value = value[0]
    if not isinstance(value, dict):
        raise ImpervaError(f"Unexpected response when reading policy {policy_id}: {value!r}")
    return value


def _ip_settings(policy):
    return [s for s in (policy.get("policySettings") or []) if s.get("policySettingType") == "IP"]


def _blocked_entries(policy):
    return [e for s in _ip_settings(policy) for e in ((s.get("data") or {}).get("ips") or [])]


def _shape(policy):
    """Non-IP setting types and total exception count, to detect collateral changes from a PUT."""
    settings = policy.get("policySettings") or []
    return (sorted(s.get("policySettingType") or "" for s in settings if s.get("policySettingType") != "IP"),
            sum(len(s.get("policyDataExceptions") or []) for s in settings))


def _covers(entry, ip):
    """True if the blacklist entry (IP, CIDR or 'a-b' range) already includes the IP."""
    entry = str(entry).strip()
    try:
        if "-" in entry:
            start, end = (ipaddress.ip_address(p.strip()) for p in entry.split("-", 1))
            return start.version == ip.version and start <= ip <= end
        return ip in ipaddress.ip_network(entry, strict=False)
    except ValueError:
        return False


def _is_exact(entry, ip):
    """True if the blacklist entry is exactly the IP (e.g. '1.2.3.4' or '1.2.3.4/32')."""
    try:
        net = ipaddress.ip_network(str(entry).strip(), strict=False)
    except ValueError:
        return False
    return net.num_addresses == 1 and net.network_address == ip


def _to_int(value, name):
    try:
        return int(str(value).strip())
    except ValueError:
        raise ValueError(f"Invalid {name}: {value!r} (must be numeric)") from None


def _parse_inputs(policy_id, account_id, ip):
    policy_id = _to_int(policy_id, "Policy ID")
    account_id = _to_int(account_id, "Account ID") if account_id not in (None, "") else None
    try:
        ip_obj = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        raise ValueError(f"Invalid IP: {ip!r} (provide a single IPv4 or IPv6 address)") from None
    return policy_id, account_id, ip_obj


def _load_acl(session, policy_id, account_id, ip_obj):
    policy = _get_policy(session, policy_id, account_id)
    if policy.get("policyType") != "ACL":
        raise ImpervaError(f"Policy {policy_id} ({policy.get('name')}) is of type "
                           f"{policy.get('policyType')}, not ACL. Nothing was changed.")
    return policy, {"policy_id": policy_id, "policy_name": policy.get("name"), "ip": str(ip_obj)}


def block_ip(api_id, api_key, policy_id, ip, account_id=None, dry_run=False):
    """Adds `ip` to the blacklist of ACL policy `policy_id`. Returns a dict with the result.

    Raises ValueError for invalid parameters and ImpervaError for API/policy failures.
    """
    policy_id, account_id, ip_obj = _parse_inputs(policy_id, account_id, ip)
    session = _session(api_id, api_key)
    policy, result = _load_acl(session, policy_id, account_id, ip_obj)
    if policy.get("enabled") is False:
        result["warning"] = "The policy is disabled: the IP is on the blacklist but is not being blocked."

    before = _blocked_entries(policy)
    match = next((e for e in before if _covers(e, ip_obj)), None)
    if match is not None:
        return {**result, "status": "already_blocked", "matched_entry": match}

    # With the existing setting id, the POST appends the IP to the current list.
    # If the ACL has no IP blacklist yet (only GEO/URL, for example), the setting is created.
    setting = {"policySettingType": "IP", "settingsAction": "BLOCK", "data": {"ips": [str(ip_obj)]}}
    ip_settings = _ip_settings(policy)
    if ip_settings:
        setting["id"] = ip_settings[0].get("id")
        setting["settingsAction"] = ip_settings[0].get("settingsAction") or "BLOCK"

    payload = {
        # Fields required by PolicyDto, resent with their current values (no change).
        "name": policy.get("name"),
        "enabled": policy.get("enabled"),
        "policyType": policy.get("policyType"),
        "policySettings": [setting],
    }

    if dry_run:
        return {**result, "status": "dry_run",
                "request": {"method": "POST", "url": API_URL.format(policy_id=policy_id),
                            "caid": account_id, "body": payload}}

    updated = _call(session, "POST", policy_id, account_id, payload=payload)
    if not isinstance(updated, dict) or "policySettings" not in updated:
        updated = _get_policy(session, policy_id, account_id)

    after = _blocked_entries(updated)
    if not any(_covers(e, ip_obj) for e in after):
        raise ImpervaError("The API accepted the change, but the IP does not appear on the policy blacklist.")
    lost = sorted(set(before) - set(after))
    if lost:
        raise ImpervaError(f"WARNING: the IP was added, but {len(lost)} previous entr(y/ies) disappeared "
                           f"from the blacklist and must be restored: {lost}")

    return {**result, "status": "added", "total_entries": len(after)}


def unblock_ip(api_id, api_key, policy_id, ip, account_id=None, dry_run=False):
    """Removes `ip` from the blacklist of ACL policy `policy_id`. Returns a dict with the result.

    Only entries that are exactly this IP are removed. If the IP is covered by a CIDR or range,
    nothing is changed and ImpervaError is raised. The removal is a full PUT built from the policy
    read just before, so a block running at the same moment on the same policy can be lost:
    on the SOAR side, do not run block/unblock in parallel for the same policy.

    Raises ValueError for invalid parameters and ImpervaError for API/policy failures.
    """
    policy_id, account_id, ip_obj = _parse_inputs(policy_id, account_id, ip)
    session = _session(api_id, api_key)
    policy, result = _load_acl(session, policy_id, account_id, ip_obj)

    before = _blocked_entries(policy)
    removed = [e for e in before if _is_exact(e, ip_obj)]
    if not removed:
        covering = next((e for e in before if _covers(e, ip_obj)), None)
        if covering is not None:
            raise ImpervaError(f"IP {ip_obj} is blocked by the entry {covering!r} (CIDR/range), "
                               "which is not removed automatically. Nothing was changed.")
        return {**result, "status": "not_blocked"}

    shape_before = _shape(policy)
    for setting in _ip_settings(policy):
        data = setting.get("data") or {}
        if data.get("ips"):
            data["ips"] = [e for e in data["ips"] if not _is_exact(e, ip_obj)]

    # PUT replaces the whole policy: every field is sent exactly as read, minus the IP.
    payload = {k: policy[k] for k in PUT_FIELDS if k in policy}

    if dry_run:
        return {**result, "status": "dry_run", "removed_entries": removed,
                "request": {"method": "PUT", "url": API_URL.format(policy_id=policy_id),
                            "caid": account_id, "body": payload}}

    _call(session, "PUT", policy_id, account_id, payload=payload)
    updated = _get_policy(session, policy_id, account_id)  # confirm against a fresh read

    after = _blocked_entries(updated)
    if any(_is_exact(e, ip_obj) for e in after):
        raise ImpervaError("The API accepted the change, but the IP is still on the policy blacklist.")
    lost = sorted(set(before) - set(removed) - set(after))
    if lost:
        raise ImpervaError(f"WARNING: the IP was removed, but {len(lost)} other entr(y/ies) also disappeared "
                           f"from the blacklist and must be restored: {lost}")
    shape_after = _shape(updated)
    if shape_after != shape_before:
        raise ImpervaError(f"WARNING: the IP was removed, but other settings/exceptions of the policy changed "
                           f"(before: {shape_before}, after: {shape_after}). Review the policy.")

    return {**result, "status": "removed", "removed_entries": removed, "total_entries": len(after)}


ACTIONS = {"block": block_ip, "unblock": unblock_ip}


def _emit(result, code):
    print(json.dumps(result))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Blocks or unblocks an IP on the blacklist of an Imperva Cloud WAF ACL policy.",
        epilog=f"Developed by {__author__} - contact: {__email__}")
    parser.add_argument("--action", default=os.getenv("IMPERVA_ACTION"),
                        help="block (default) or unblock. env: IMPERVA_ACTION")
    for dest, flag, env, required in PARAMS:
        parser.add_argument(flag, dest=dest, default=os.getenv(env),
                            help=f"env: {env}" + ("" if required else " (optional)"))
    parser.add_argument("--dry-run", action="store_true",
                        help="Only read the policy and show what would be sent, without changing anything.")
    args = parser.parse_args(argv)

    action = (args.action or "block").strip().lower()
    if action not in ACTIONS:
        return _emit({"status": "error", "error": f"Invalid action: {args.action!r} (use block or unblock)"}, 2)

    missing = [f"{flag} / {env}" for dest, flag, env, required in PARAMS
               if required and not getattr(args, dest)]
    if missing:
        return _emit({"status": "error", "error": "Missing parameters: " + ", ".join(missing)}, 2)

    try:
        result = ACTIONS[action](args.api_id, args.api_key, args.policy_id, args.ip,
                                 account_id=args.account_id, dry_run=args.dry_run)
    except ValueError as exc:
        return _emit({"status": "error", "error": str(exc)}, 2)
    except ImpervaError as exc:
        return _emit({"status": "error", "error": str(exc)}, 1)
    return _emit(result, 0)


if __name__ == "__main__":
    sys.exit(main())
