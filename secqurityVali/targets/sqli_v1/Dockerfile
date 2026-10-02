# The SQLi benchmark target. Deliberately vulnerable; runs ONLY inside the
# validator's isolated sandbox, never on a real network.
#
# Stdlib only -- python:3.12-slim needs nothing installed. The per-run
# challenge (canary, schema, endpoints) is injected as environment variables at
# `docker run` time by the orchestrator (see provision.py), so the image itself
# is generic and holds no secret.
FROM python:3.12-slim

WORKDIR /app
COPY app.py /app/app.py

EXPOSE 8000
ENTRYPOINT ["python", "/app/app.py"]
