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


def test_internet_socket_is_high():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] wget E socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)'
    report = analyze(log)
    assert report.violations[0].severity == SEV_HIGH
    assert report.violations[0].kind == "network-socket"


def test_outbound_connect_is_high():
    log = 'I0928 10:00:00.0 1 strace.go:572] [ 1: 1] agent E connect(3, {Family: AF_INET, Addr: 1.1.1.1, Port: 443}, 16)'
    report = analyze(log)
    assert report.violations[0].kind == "network-connect"
    assert report.violations[0].severity == SEV_HIGH


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
