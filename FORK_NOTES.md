# Fork notes

## Upstream

- Upstream: https://github.com/emiliensocchi/entra-ca-insight
- Fork: https://github.com/chryzsh/entra-ca-insight
- `main` tracks upstream.

## Purpose

Offline Conditional Access gap analysis from a roadrecon database (`roadrecon.db`). This is for cases where a roadrecon dump exists but an MS Graph token with policy read rights does not.

## Branches

- `feature/roadrecon-backend`: adds the `--roadrecon-db` CLI flag and an offline backend.

## Changes

- `caInsight/graph/roadrecon_client.py`: `RoadreconClient`, a subclass of `GraphAPIClient`. It overrides every method that calls MS Graph and reads from the SQLite database (read-only) instead. Its HTTP session refuses all requests. Data that roadrecon does not collect is returned as an empty list, with a warning.
- `caInsight/graph/roadrecon_translator.py`: converts AAD Graph PolicyDetail JSON (policy types 18, 6 and 44) to MS Graph `conditionalAccessPolicy`, `namedLocation` and `authenticationStrengthPolicy` objects.
- `caInsight/analyzer/policy_flattener.py`: the PIM eligibility lookups use the client's own methods when it has them, instead of calling MS Graph directly.
- `caInsight/reports/generator.py`: tenant ID and primary domain come from the client when there is no token. This skips the `/organization` call.
- `caInsight/main.py`: `--roadrecon-db PATH` is mutually exclusive with `--token`. Token mode is unchanged.
- `README.md`: section on offline analysis, inferred mappings and gaps in the data.

Not changed: `web/api_server.py`. The web scan form still needs a token.

## Known upstream behaviour

These are not fixed in this fork.

- The dashboard in `templates/portal-template.html` (around lines 3415-3430) scales the MFA, auth strength, block and gap percentages so that they sum to 100%. Identities that were evaluated and had no gap belong to none of the four groups, so they are left out of the sum. The scaled percentages therefore overstate both gaps and universal coverage.
- `UserMapper.populate_applications_cache` removes application values from policies when they do not resolve to a service principal. This includes keywords such as `Office365` and `MicrosoftAdminPortals`.
- The `applications.json` cache is keyed by service principal object ID, but policies reference applications by appId.
