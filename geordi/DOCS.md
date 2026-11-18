# Geordi v0.4.0 — Home Assistant app preview

## Purpose

Geordi independently scans GitHub release assets and pinned source snapshots of Marketplace extensions. This preview can **poll, queue, compare and notify**, but its static detection coverage is incomplete and it has not been validated on an actual HA OS instance. Do not use its output as approval to install an extension.

## Installation

Copy the entire local app directory to `/addons/geordi`, open **Settings → Apps**, refresh the local app list, install Geordi and enable its sidebar panel. The Docker image is built locally and may require network access for the base image. Home Assistant OS or Supervised is required for this app package.

## Permissions and network requests

`homeassistant_api: true` is needed for read-only inventory (`marketplace/repositories/list` or older `hacs/repositories/list`) and for **Home Assistant notifications** (`persistent_notification.create`, optionally `notify.<configured-service>` after querying the fixed `/core/api/services` endpoint). The Supervisor token grants broader authority than Geordi intentionally exercises, so the app should be treated as security-sensitive.

There is **no** `/config` mapping, host port, Docker access, Supervisor admin permission or arbitrary HA template access. The scanner gets source archives from `api.github.com` and `codeload.github.com`; selected release assets can redirect to allowlisted `release-assets.githubusercontent.com` or `objects.githubusercontent.com` with API credentials removed. Optional OSV advisory checks call `api.osv.dev`. The external package query transmits only package names, ecosystem and exact versions when `advisory_rechecks` is enabled.

## Options

- `monitor_enabled` (default `true`): automatic scanning on/off. Inventory can still be read while scans are paused.
- `poll_minutes` (default `5`, range 1–1440): interval between Marketplace inventory polls. This is **polling**, not yet a Marketplace event subscription.
- `daily_scan_limit` (default `12`, range 1–24): UTC daily quota for automatic code scans. Manual scans are not counted.
- `advisory_rechecks` (default `false`): opt-in OSV checks during source scans, plus a per-target recheck after 24 hours while idle.
- `notify_service` (default empty): exact Home Assistant `notify` service name without the `notify.` prefix, e.g. `mobile_app_my_phone`. A missing or unadvertised service is not called. Bell notifications remain enabled.
- `github_token` (default empty): optional GitHub API token to increase rate limits.

Restart the app to apply option changes. The persistent queue and scan history are in `/data/scans.db`.

## Monitoring behavior

Geordi queues installed and offered versions on first run, prioritizing offered updates. It polls again and adds new installs, changed installed versions and newly offered refs. One scan starts at a time. Completed versions are not rescanned just because the app restarts; errors are retried with delay. This design does not currently detect malicious rewrites of an unchanged tag/ref.

When Geordi discovers high/critical findings or a changed extension/ref, it sends a Home Assistant bell alert; an opt-in verified mobile service can also be called. It does not send raw source lines, URLs or snippets from analyzed code. Report comparisons are available under the *Compare* link when both installed and offered versions were scanned.

If OSV is enabled, a recheck adds a new immutable scan-history entry only after the full advisory query succeeds. Partial lookups do not replace older findings. Advisory queries do not re-open any source code and only assess explicitly pinned dependencies currently represented in the report.

## Security limitations

Release ZIPs and dashboard-card assets can now be selected directly from pinned-version GitHub release metadata, but exact local installed-byte comparison remains unavailable; source-layout selections are only approximate. Semgrep uses an offline Bubblewrap network/filesystem namespace and five initial rules. A namespace failure disables that analyzer and marks its scan incomplete. Dependency resolution for Python remains incomplete; GuardDog, full publisher history and comprehensive cross-file dataflow are not implemented. Reports are intentionally marked incomplete. The current image is not signature-verified, does not ship a custom AppArmor profile and has not undergone a formal security audit or live HA OS deployment test.

## v0.4.0 artifact selection and Semgrep checks

Geordi first resolves the version to a commit. It reads that version's `hacs.json` and chooses the integration release ZIP (if `zip_release`), the dashboard card release files (if published), or the documented source folder. The chosen payload has a SHA-256 recorded. Missing or ambiguous required release ZIPs produce a failed scan rather than scanning source as a substitute. The scanner never installs, imports or executes target code.

Semgrep uses bundled local rules only. In the HA app image, Bubblewrap isolates the process from the network, app database, HA configuration and Supervisor token. If rootless namespaces are prohibited on your host, Semgrep is **not run**; the report is incomplete. Semgrep is also not a proof of safety when it runs successfully. The image build validates the bundled rule syntax, but has not been verified in a live HA OS installation.

Before deployment, check that the resulting image runs on your Home Assistant architecture and that the scanner diagnostics show Semgrep completed rather than unavailable. **Do not treat an incomplete scan as approval to install an update.**
