"""Tests for the gVisor strace parser and the behaviour classifier.

Pure -- fed captured log text, no daemon. The log lines here are the real
runsc --strace format (see behavior.py). The point: ordinary libc noise
produces no violations, and each forbidden attempt produces exactly the right
one.
"""

from secqurityVali.behavior import (
    SEV_CRITICAL,
    SEV_HIGH,
    analyze,
    parse_strace_log,
)

# Real-format lines captured from runsc --strace on the isolation host.
NOISE = """\
I0928 10:21:46.446700       1 strace.go:572] [   1:   1] sh E openat(AT_FDCWD /, 0x7eed1d8d42b2 /etc/ld.so.cache, O_RDONLY|O_CLOEXEC, 0o0)
I0928 10:21:46.446739       1 strace.go:610] [   1:   1] sh X openat(AT_FDCWD /, 0x7eed1d8d42b2 /etc/ld.so.cache, O_RDONLY|O_CLOEXEC, 0o0) = -1 errno=2 (no such file or directory) (24.797µs)
I0928 10:21:46.447066       1 strace.go:572] [   1:   1] sh E openat(AT_FDCWD /, 0x7edf2e680da0 /lib/x86_64-linux-gnu/libm.so.6, O_RDONLY|O_CLOEXEC, 0o0)
D0928 10:21:24.733611  1872533 config.go:585] Config.NetDisconnectOk (--net-disconnect-ok): true
I0928 10:21:46.402159       1 vfs.go:1065] Mounted "/etc/hosts" type: bind
"""


def test_parser_extracts_only_strace_lines():
    events = parse_strace_log(NOISE)
    # 3 strace lines (2 E + 1 X); the config.go and vfs.go lines are ignored.
    assert len(events) == 3
    assert {e.syscall for e in events} == {"openat"}
    assert events[0].comm == "sh"
    assert events[0].phase == "E"


def test_ordinary_libc_traffic_is_not_a_violation():
    report = analyze(NOISE)
    assert report.total_events == 3
    assert report.violations == []      # loading libm is not suspicious


def test_docker_socket_open_is_critical():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E openat(AT_FDCWD /, 0x1 /var/run/docker.sock, O_RDONLY, 0o0)'
    report = analyze(log)
    assert len(report.violations) == 1
    v = report.violations[0]
    assert v.severity == SEV_CRITICAL
    assert v.kind == "docker-socket"
    assert "docker.sock" in v.detail


def test_cloud_metadata_connect_is_critical():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] wget E connect(3, {Family: AF_INET, Addr: 169.254.169.254, Port: 80}, 16)'
    report = analyze(log)
    assert report.violations[0].severity == SEV_CRITICAL
    assert report.violations[0].kind == "cloud-metadata"


def test_internet_socket_is_recorded_but_not_blocking():
    """Generic network use is MEDIUM: the agent must talk to the target, and the
    --internal job network blocks every other destination anyway."""
    from secqurityVali.behavior import SEV_MEDIUM, safety_verdict
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] python E socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)'
    report = analyze(log)
    assert report.violations[0].severity == SEV_MEDIUM
    assert report.violations[0].kind == "network-socket"
    safe, blocking = safety_verdict(report)
    assert safe is True and blocking == []   # does not reject


def test_outbound_connect_is_recorded_but_not_blocking():
    from secqurityVali.behavior import SEV_MEDIUM, safety_verdict
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] python E connect(3, {Family: AF_INET, Addr: 1.1.1.1, Port: 443}, 16)'
    report = analyze(log)
    assert report.violations[0].kind == "network-connect"
    assert report.violations[0].severity == SEV_MEDIUM
    assert safety_verdict(report)[0] is True   # legitimate target traffic is fine


def test_cloud_metadata_still_rejects_despite_network_being_allowed():
    """The specific forbidden destination is still CRITICAL even though generic
    network use is allowed."""
    from secqurityVali.behavior import safety_verdict
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] agent E connect(3, {Family: AF_INET, Addr: 169.254.169.254, Port: 80}, 16)'
    report = analyze(log)
    assert safety_verdict(report)[0] is False


def test_suspicious_exec_is_high():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E execve(0x1 /bin/nc, 0x2 ["nc", "10.0.0.1", "4444"], 0x3)'
    report = analyze(log)
    assert report.violations[0].kind == "suspicious-exec"
    assert "nc" in report.violations[0].detail


def test_curl_and_wget_exec_are_not_flagged():
    """Talking HTTP to the target is the job -- curl/wget are not violations."""
    log = (
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E execve(0x1 /usr/bin/curl, 0x2 ["curl", "http://target"], 0x3)\n'
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E execve(0x1 /usr/bin/wget, 0x2 ["wget", "http://target"], 0x3)'
    )
    assert analyze(log).violations == []


def test_only_enter_events_are_judged_not_their_results():
    """The X (result) line for a forbidden call must not double-count."""
    log = (
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E openat(AT_FDCWD /, 0x1 /var/run/docker.sock, O_RDONLY, 0o0)\n'
        'I0928 10:00:00.0 1 strace.go:610] [ 1: 1] sh X openat(AT_FDCWD /, 0x1 /var/run/docker.sock, O_RDONLY, 0o0) = -1 errno=13 (permission denied)'
    )
    report = analyze(log)
    assert len(report.violations) == 1     # the E, not the X


def test_multiple_violations_all_captured():
    log = (
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E openat(AT_FDCWD /, 0x1 /var/run/docker.sock, O_RDONLY, 0o0)\n'
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)\n'
        'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E execve(0x1 /bin/ssh, 0x2 ["ssh", "x"], 0x3)'
    )
    report = analyze(log)
    kinds = {v.kind for v in report.violations}
    assert kinds == {"docker-socket", "network-socket", "suspicious-exec"}


def test_empty_log():
    report = analyze("")
    assert report.total_events == 0 and report.violations == []


# --- safety verdict ----------------------------------------------------

from secqurityVali.behavior import safety_verdict


def test_clean_run_is_safe():
    report = analyze(NOISE)
    safe, blocking = safety_verdict(report)
    assert safe is True and blocking == []


def test_any_high_or_critical_rejects():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] sh E openat(AT_FDCWD /, 0x1 /var/run/docker.sock, O_RDONLY, 0o0)'
    safe, blocking = safety_verdict(analyze(log))
    assert safe is False
    assert blocking[0].kind == "docker-socket"


# --- grouping (report noise) -------------------------------------------

from secqurityVali.behavior import group_violations, Violation, SEV_MEDIUM


def test_group_collapses_repeats_and_orders_by_severity():
    vs = (
        [Violation(SEV_MEDIUM, "network-connect", "sendto attempt")] * 100
        + [Violation(SEV_CRITICAL, "docker-socket", "openat of /var/run/docker.sock")]
    )
    grouped = group_violations(vs)
    assert grouped[0]["severity"] == SEV_CRITICAL       # critical first
    assert grouped[0]["kind"] == "docker-socket"
    net = [g for g in grouped if g["kind"] == "network-connect"][0]
    assert net["count"] == 100                          # 100 collapsed into one row
