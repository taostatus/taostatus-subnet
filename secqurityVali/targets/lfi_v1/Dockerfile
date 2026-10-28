# The path-traversal / LFI benchmark target. DELIBERATELY vulnerable; runs ONLY
# inside the validator's isolated sandbox (gVisor, --internal, no egress).
#
# Stdlib only. The per-run challenge is injected as environment variables at
# `docker run` time (see provision.py). The app seeds the canary into /flag
# (OUTSIDE the served directory) and the decoy files into /srv/files at startup,
# then scrubs the env, so the canary is reachable only by traversing out.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

# Non-root; /flag (outside the served dir) and /srv/files are owned by that user
# so the app can seed them, but nothing in the image is privileged.
RUN useradd -m -u 10001 appuser \
 && mkdir -p /srv/files && touch /flag \
 && chown -R appuser:appuser /srv/files /flag && chmod 600 /flag
USER appuser

EXPOSE 8000
ENTRYPOINT ["python", "/app/app.py"]
