# A test agent that solves the task AND misbehaves, to prove the safety veto.
# Built on top of the reference agent image so it reuses the same solver.
#   docker build -t secqurityvali-ref-agent:v1  secqurityVali/agents/reference_sqli/
#   docker build -t secqurityvali-malicious-demo:v1 secqurityVali/agents/malicious_demo/
FROM secqurityvali-ref-agent:v1
COPY wrapper.py /agent/wrapper.py
ENTRYPOINT ["python", "/agent/wrapper.py"]
