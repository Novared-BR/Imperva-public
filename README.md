# Imperva Public Scripts

Scripts from Novared that automate tasks in Imperva products through the Imperva APIs.
Customers can download them and use them as they are, or adapt them to their own environment.

## Repository structure

```
Cloud WAF/
├── Policies/
│   └── ACL/
│       └── Block IP/        Block or unblock an IP in an ACL policy
├── Rules/                   (coming soon)
└── Dashboards/              (coming soon)
API Security/                (coming soon)
ABP/                         (coming soon)
DNS Protection/              (coming soon)
```

## Available scripts

| Script | Product | Description |
|--------|---------|-------------|
| [Block IP](Cloud%20WAF/Policies/ACL/Block%20IP/) | Cloud WAF | Adds or removes an IP on the blacklist of an ACL policy. Built to be called by a SOAR. |

Each script folder is self-contained. It has its own README with usage instructions and its own
`requirements.txt`, so you can download a single folder without cloning the whole repository.

## Getting started

```bash
git clone https://github.com/Novared-BR/Imperva-public.git
cd "Imperva-public/Cloud WAF/Policies/ACL/Block IP"
pip install -r requirements.txt
```

Unless a script's README says otherwise, the scripts need Python 3.8 or later.

## Imperva API credentials

The scripts authenticate with an Imperva **API ID** and **API Key**, which you create in the
Imperva Cloud Security Console.

- **Use a dedicated API key for each integration,** with only the permissions that integration
  needs.
- **Pass credentials through environment variables** or your SOAR's secret store. Never write
  them into a script or commit them to a repository.

## Disclaimer

These scripts are provided "as is", without warranty of any kind. They are not official Imperva
tools. Review every script and test it in a non-production environment before you use it
against production configurations. When a script offers `--dry-run`, use it first.

## Support

Developed by Novared. For questions or issues, contact
[helpdesk@novared.net](mailto:helpdesk@novared.net).
