"""Tests for turning a Challenge into the target's environment.

The target the agent attacks and the answer key the scorer uses must be the
same Challenge seen from two sides -- these tests pin that.
"""

import json

from secqurityVali.eval.challenge import generate_challenge
from secqurityVali.targets.sqli_v1.provision import (
    docker_env_args,
    target_env,
)


def test_env_carries_every_challenge_value():
    c = generate_challenge()
    env = target_env(c)
    assert env["SQLI_CANARY"] == c.canary
    assert env["SQLI_SECRET_TABLE"] == c.secret_table
    assert env["SQLI_SECRET_COLUMN"] == c.secret_column
    assert env["SQLI_VULN_ENDPOINT"] == c.vulnerable_endpoint
    assert env["SQLI_VULN_PARAM"] == c.vulnerable_parameter
    assert env["SQLI_ERROR_TRAP"] == c.error_trap_endpoint


def test_all_endpoints_is_vulnerable_plus_decoys():
    c = generate_challenge()
    all_eps = json.loads(target_env(c)["SQLI_ALL_ENDPOINTS"])
    assert c.vulnerable_endpoint in all_eps
    for decoy in c.safe_endpoints:
        assert decoy in all_eps
    # exactly one vulnerable + the decoys, no duplicates
    assert len(all_eps) == 1 + len(c.safe_endpoints)


def test_error_trap_is_one_of_the_decoys_not_the_vulnerable_one():
    c = generate_challenge()
    assert c.error_trap_endpoint in c.safe_endpoints
    assert c.error_trap_endpoint != c.vulnerable_endpoint


def test_docker_env_args_are_flag_value_pairs():
    c = generate_challenge()
    args = docker_env_args(c)
    # every -e is followed by a KEY=VALUE
    assert args.count("-e") == len(target_env(c))
    for i in range(0, len(args), 2):
        assert args[i] == "-e"
        assert "=" in args[i + 1]


def test_the_agent_never_gets_the_answer():
    """Sanity: the target env is for the TARGET container. It must never be
    handed to the agent -- these tests just document that the canary lives in
    the target's env, which the agent cannot read."""
    c = generate_challenge()
    env = target_env(c)
    assert c.canary in env.values()   # present for the target...
    # ...and the whole point of the sandbox is the agent can't read the
    # target's process env; it can only reach the target over HTTP.


def test_env_carries_the_variant():
    from secqurityVali.targets.sqli_v1.provision import target_env
    c = generate_challenge()
    assert target_env(c)["SQLI_VARIANT"] == c.variant
