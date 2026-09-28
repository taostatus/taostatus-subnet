# The reference SQLi agent, as an image the job can run like any miner's agent.
# Stdlib only, so nothing to install. It reads TARGET_URL / OUTPUT_PATH / RUN_ID
# from the environment (the job sets them) and writes /out/findings.json.
FROM python:3.12-slim
WORKDIR /agent
COPY agent.py /agent/agent.py
# Non-root: the agent has no reason to run as root, and the job can require it.
RUN useradd -u 10001 -m runner
USER 10001
ENTRYPOINT ["python", "/agent/agent.py"]
