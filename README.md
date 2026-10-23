# 🧿 CA Insight ![Vibe Coded](https://img.shields.io/badge/vibe-coded-blueviolet?style=flat-square)

Discover gaps in Entra Conditional Access policies before attackers do.


## 📑 Instructions

See the [project's wiki](https://github.com/emiliensocchi/entra-ca-insight/wiki) for more information about CA Insight's design, analysis workflows, installation and usage. 


## 🕳️ What is a Conditional Access Gap?

A **gap** is a specific combination of access conditions (identity, application, platform, location, client type, etc.) for which **no Conditional Access policy enforces a strong control**, causing access to fall back to username and password.

CA Insight defines the following as **strong controls**:
- **Block access**
- **Grant access** with **Multi-Factor Authentication (MFA)**
- **Grant access** with **Authentication strength** (e.g. phishing-resistant MFA)

**Example Gap:**
```
User: john.doe@contoso.com
Application: Office 365
Platform: iOS
Location: Public WiFi (untrusted network)
Client Type: Browser
Auth Flow: Standard

Result: No policy requires MFA, Auth Strength or blocks access → GAP!
```

In this scenario, John can access the Office 365 application (with sensitive corporate data) from an unmanaged iOS device on public WiFi using a username and password.


## 🎯 Why CA Insight?

### 📑 Traditional approach

Traditional gap detection relies on analyzing **Entra sign-in logs** to discover successful sign ins where no conditional access policy is applied. This approach comes with 2 main disadvantages: 

1. **Purely reactive** - A gap is only discovered **after** it has already been used or exploited.
2. **Unused gaps remain unknown** - Gaps that have not been (mis)used yet do not appear in sign-in logs and remain undiscovered.

### 🧿 CA Insight's approach

Inspired by [Joosua Santasalo](https://github.com/jsa2)'s research on the now-archived [caOptics](https://github.com/jsa2/caOptics) project, **CA Insight** takes an **identity-centric** approach to enumerate **all possible access combinations**, and evaluate each of them against the tenant's Conditional Access policy configuration.

This approach comes with 2 main advantages:

1. **Purely proactive** - All gaps are discovered **before** they are used or exploited.

2. **Minimal API interaction** - Once policies and other necessary Entra objects have been retrieved from the MS Graph API, access combinations are generated and **evaluated offline**. This minimizes the amount of requests necessary for the analysis, and provides a **scalable** approach to analyze large tenants with thousands of identities.


## ✨ Key Features

- **🖥️ Dual Interface** - **CLI** for automation, CI/CD pipelines, and scripted analysis | **Web Portal** for interactive exploration, live scan monitoring, and visual gap analysis with dashboards.

- **👥 Comprehensive Identity Coverage** - Analyze **all identity types**: agent identities, guests and external users, member users, workload identities.

- **🔮 Proactive Gap Detection** - Generate and evaluate **all possible access combinations** offline before they're exploited, discovering gaps that would never appear in sign-in logs.

- **🎯 Advanced Filtering & Scoping** - Scope analysis with **identity filters** (include/exclude specific identities), **target specific resources** (agent resources, cloud apps, user actions), automatically **exclude irrelevant policies** from gap detection.

- **📊 Historical Tracking & Comparison** - Track **scan history** across multiple runs, monitor **universal coverage trends** (Auth Strength, MFA, Block), compare configurations over time, and **export results** for compliance reporting.


## 🗄️ Offline Analysis from a roadrecon Database

CA Insight can read policies and directory data from a [roadrecon](https://github.com/dirkjanm/ROADtools) database instead of calling MS Graph. Use `--roadrecon-db` in place of `--token`:

```bash
python -m caInsight --roadrecon-db roadrecon.db --include-assignments users --target-resources cloud-apps
```

In this mode CA Insight opens the database read-only, needs no token, and makes no network calls. It writes `cache/`, `portal.html` and the reports to the current directory, as in token mode. Run it from an empty working directory, or use `--clear-cache all`, so that caches from token mode and roadrecon mode do not mix.

The web portal can display reports from roadrecon mode, but the scan form in the web portal still needs a token. Start roadrecon scans from the CLI.

### How the data is mapped

roadrecon stores Conditional Access policies (policy type 18), named locations (type 6) and custom authentication strengths (type 44) in the AAD Graph format. CA Insight converts them to the MS Graph format before analysis. The mapping follows roadrecon's own policy parser (`roadrecon/plugins/policies.py`).

These mappings are inferred and not confirmed against MS Graph output:

| AAD value | MS Graph value |
| --- | --- |
| Auth flow `QrCode` | `authenticationTransfer` |
| GUID in a grant `Control` list | `termsOfUse` agreement ID |
| Guest criterion without `ExternalTenants` | `externalTenants.membershipKind: all` |
| Service principal criterion with `IsAgentic: true` | `include/excludeAgentIdServicePrincipals` |
| `CountryLookupMethod` 0 / 1 | `clientIpAddress` / `authenticatorAppGps` |
| More than one `Controls` entry | `operator: AND` (one entry with several controls is `OR`) |
| `MfaAndChangePassword` | `mfa` + `passwordChange`, `operator: AND` |

### Data that roadrecon does not provide

roadrecon does not collect the following. CA Insight returns an empty list and prints a one-line warning:

- Authentication contexts. Policies that use them are already excluded from gap analysis.
- Agent identities, agent blueprints and agent resources.
- PIM for Groups eligibility. PIM role eligibility is read from the `EligibleRoleAssignments` table.

These MS Graph fields have no equivalent in the roadrecon policy data. They are left empty or null:

- `sessionControls.signInFrequency.authenticationType`
- `sessionControls.cloudAppSecurity.cloudAppSecurityType`. The AAD number is shown as "unmapped".
- `conditions.times`, `conditions.applications.applicationFilter`, `partialEnablementStrategy`
- `grantControls.customAuthenticationFactors`
- `allowedCombinations` of custom authentication strengths stays in the AAD format.
- The user `identities` property. B2B collaboration members are detected by `#EXT#` in the user principal name instead.


## 📸 Screenshots

### CLI Interface

**Running a scan from the command line:**
![CLI Scan](assets/images/01_cli_scan.png)

### Web Portal

**Start New Scan - Running a scan from the CA Insight portal:**
![Scan Management 1](assets/images/01_Scan_Management_01.png)

**Scan History - Tracking scan history per tenant:**
![Scan Management 2](assets/images/01_Scan_Management_02.png)

**Gap Analysis - Visualizing scan details with statistics and analysis results:**
![Gap Analysis Details 1](assets/images/02_Gap_Analysis_01.png)

**Gap Analysis - Browsing specific gaps to visualize uncovered access paths:**
![Gap Analysis Details 2](assets/images/02_Gap_Analysis_02.png)

**Policy Browser - Exploring all tenant policies in one centralized view for efficient root cause analysis:**
![Policy Browser](assets/images/03_Policy_Browser.png)


## 📢 Disclaimer

CA Insight is **not** a Microsoft service or product. It is a personal project provided as-is for analyzing Conditional Access policy configurations, without any explicit or implicit obligations. 

CA Insight performs **read-only operations** and does not modify any policies or settings in your Entra ID tenant. Always validate findings in a non-production environment before making policy changes. The authors are **not responsible** for any misconfigurations or security issues resulting from the use of this tool.
