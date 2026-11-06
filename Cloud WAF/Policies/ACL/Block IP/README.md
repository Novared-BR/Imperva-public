# Block IP - Imperva Cloud WAF ACL policy

Adds an IP address to the IP blacklist of an Imperva Cloud WAF **ACL policy**, or removes it.
It is built to be called by a SOAR playbook, but it can also be run by hand.

The script uses the Imperva Policy Management API v2. Every website the policy is applied to
starts blocking the IP as soon as the policy is updated.

## Requirements

- Python 3.8 or later
- The dependencies: `pip install -r requirements.txt`
- An Imperva **API ID** and **API Key** that can read and edit policies on the account
- An existing **ACL policy** that is applied to the websites you want to protect. To find its
  ID, list the account's policies with `GET https://api.imperva.com/policies/v2/policies`.

## Parameters

Every parameter can be passed as a command-line argument or as an environment variable.
If both are set, the command-line argument wins.

| Argument       | Environment variable | Required | Description |
|----------------|----------------------|----------|-------------|
| `--action`     | `IMPERVA_ACTION`     | No       | `block` (default) or `unblock` |
| `--api-id`     | `IMPERVA_API_ID`     | Yes      | Imperva API ID |
| `--api-key`    | `IMPERVA_API_KEY`    | Yes      | Imperva API Key. Prefer the environment variable, because command-line arguments show up in the process list. |
| `--policy-id`  | `IMPERVA_POLICY_ID`  | Yes      | ID of the ACL policy |
| `--ip`         | `IMPERVA_BLOCK_IP`   | Yes      | One IPv4 or IPv6 address. CIDRs and ranges are rejected on purpose, so a bad input cannot block a whole network. |
| `--account-id` | `IMPERVA_ACCOUNT_ID` | No       | Only needed when the policy belongs to a sub-account of the API key's account (sent to the API as `caid`) |
| `--dry-run`    | -                    | No       | Reads the policy and prints the request that would be sent, without changing anything |

## Usage

### Linux / macOS

```bash
export IMPERVA_API_ID=12345
export IMPERVA_API_KEY=your-api-key
export IMPERVA_POLICY_ID=67890

python3 policy_blacklist.py --ip 203.0.113.7                    # block
python3 policy_blacklist.py --ip 203.0.113.7 --action unblock   # unblock
python3 policy_blacklist.py --ip 203.0.113.7 --dry-run          # preview, changes nothing
```

### Windows (PowerShell)

```powershell
$env:IMPERVA_API_ID = "12345"
$env:IMPERVA_API_KEY = "your-api-key"
$env:IMPERVA_POLICY_ID = "67890"

python policy_blacklist.py --ip 203.0.113.7
python policy_blacklist.py --ip 203.0.113.7 --action unblock
```

### As a Python module

```python
from policy_blacklist import block_ip, unblock_ip, ImpervaError

result = block_ip(api_id, api_key, policy_id, "203.0.113.7")
result = unblock_ip(api_id, api_key, policy_id, "203.0.113.7", account_id=None)
```

Both functions return the same dictionary the command line prints. They raise `ValueError`
for invalid parameters and `ImpervaError` for API errors or an unexpected policy state.

## Output

The script prints a single JSON line on stdout, for example:

```json
{"policy_id": 67890, "policy_name": "SOAR blocklist", "ip": "203.0.113.7", "status": "added", "total_entries": 42}
```

| `status`          | Exit code | Meaning |
|-------------------|-----------|---------|
| `added`           | 0 | The IP was added to the blacklist |
| `already_blocked` | 0 | The IP was already covered by an IP, CIDR or range on the blacklist (`matched_entry`). Nothing was changed. |
| `removed`         | 0 | The IP was removed (`removed_entries`) |
| `not_blocked`     | 0 | The IP was not on the blacklist. Nothing was changed. |
| `dry_run`         | 0 | Nothing was changed. `request` shows what would have been sent. |
| `error`           | 1 | API error or unexpected policy state (`error` has the details) |
| `error`           | 2 | Missing or invalid parameter |

When the policy is disabled, a block also returns a `warning` field. The IP is on the
blacklist, but nothing is blocked until the policy is enabled again.

Running the same call twice is safe: the second run returns `already_blocked` or
`not_blocked` and does not change the policy.

## How it works

Both actions first read the policy (`GET /v2/policies/{id}?extended=true`). They stop without
changing anything if the policy is not an ACL policy, for example a whitelist.

**Block** sends a partial update (`POST /v2/policies/{id}`). The API appends the IP to the
existing list, and no other part of the policy is sent. The script then checks that the IP was
added and that no previous entry disappeared.

**Unblock** has to send a full update (`PUT /v2/policies/{id}`), because the API has no partial
removal. The script resends the whole policy exactly as it read it, minus the IP. Then it reads
the policy again to confirm three things: the IP is gone, every other entry is still there, and
the other settings and exceptions did not change. If anything else changed, it returns an error
that lists what to restore.

- **Exact entries only:** unblock removes only entries that are exactly the IP, such as
  `203.0.113.7` or `203.0.113.7/32`.
- **CIDRs and ranges are left alone:** if the IP is blocked only through a CIDR or a range,
  unblock returns an error and leaves that entry in place.

Temporary API errors (HTTP 429 and 5xx) are retried for `GET` and `PUT`. A `POST` is never
retried, so a retry cannot add the IP twice.

## Recommendations

- **Test first:** run with `--dry-run`, then run once against a non-production policy before
  connecting the script to a playbook.
- **Do not run block and unblock in parallel on the same policy.** Unblock reads the policy and
  then overwrites it. If a block lands between those two steps, that block is lost.
- **Use a dedicated API key** for the integration, and pass it through an environment variable
  or your SOAR's secret store.

## Support

Developed by Novared - [helpdesk@novared.net](mailto:helpdesk@novared.net)
