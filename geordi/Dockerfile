# Local development build. Before production release, pin and sign the base digest.
FROM python:3.13-slim-bookworm
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/opt/geordi
# Development-only build: third-party parser runs inside bwrap offline namespaces.
# Pins should be locked with hashes and image digest verified before production.
RUN apt-get update && apt-get install -y --no-install-recommends bubblewrap \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --only-binary=:all: semgrep==1.185.0
RUN groupadd -g 10001 scanner && useradd --no-log-init --uid 10001 -g 10001 --home-dir /nonexistent --shell /usr/sbin/nologin scanner \
    && mkdir -p /opt/geordi /data && chmod 0700 /data
COPY app/geordi/ /opt/geordi/geordi/
# Validate *trusted, bundled* Semgrep rules at build time; no target source involved.
RUN SEMGREP_METRICS=off semgrep scan --validate --config /opt/geordi/geordi/rules --metrics=off
# Root entrypoint performs only ownership setup on Supervisor's /data mount, then
# permanently drops UID/GID before network operations or scanning untrusted code.
CMD ["python", "-m", "geordi.launch"]
