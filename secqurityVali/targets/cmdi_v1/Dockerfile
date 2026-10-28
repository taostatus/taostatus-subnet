# The command-injection benchmark target. DELIBERATELY vulnerable; runs ONLY
# inside the validator's isolated sandbox (gVisor, --internal, no egress), never
# on a real network.
#
# Stdlib only. The per-run challenge (canary, endpoints, variant) is injected as
# environment variables at `docker run` time (see provision.py). The app seeds
# the canary into /flag at startup and scrubs it from the environment, so the
# image itself holds no secret and the canary is reachable only by executing a
# command through the injection.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

# Run as a non-root user. /flag is owned by that user so the app can seed it and
# an injected command (running as the same user) can read it -- but nothing in
# the image is privileged.
RUN useradd -m -u 10001 appuser \
 && touch /flag && chown appuser:appuser /flag && chmod 600 /flag
USER appuser

EXPOSE 8000
ENTRYPOINT ["python", "/app/app.py"]
