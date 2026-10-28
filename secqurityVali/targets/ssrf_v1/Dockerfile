# The SSRF / server-side-request-forgery benchmark target. Deliberately
# vulnerable; runs ONLY inside the validator's isolated sandbox. Stdlib only; the
# per-run challenge is injected as env vars at `docker run` (see provision.py).
FROM python:3.12-slim
WORKDIR /app
COPY app.py /app/app.py
EXPOSE 8000
ENTRYPOINT ["python", "/app/app.py"]
