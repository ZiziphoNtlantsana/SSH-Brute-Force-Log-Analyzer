from log_analyzer import find_compromised, find_brute_force_ips, find_targeted_usernames

def test_find_compromised_detects_login_after_failures():
    events = [
        {"month": "Nov", "day": "11", "time": "09:02:17", "status": "Failed", "user": "root", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:19", "status": "Failed", "user": "root", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:21", "status": "Failed", "user": "root", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:25", "status": "Accepted", "user": "root", "ip": "198.51.100.77"},
    ]
    flagged = {"198.51.100.77": 3}

    result = find_compromised(events, flagged)

    assert len(result) == 1
    assert result[0]["ip"] == "198.51.100.77"
    assert result[0]["user"] == "root"
    assert result[0]["time"] == "09:02:25"

def test_find_compromised_ignores_ip_with_no_successful_login():
    events = [
        {"month": "Nov", "day": "11", "time": "08:15:01", "status": "Failed", "user": "root", "ip": "203.0.113.5"},
        {"month": "Nov", "day": "11", "time": "08:15:03", "status": "Failed", "user": "admin", "ip": "203.0.113.5"},
        {"month": "Nov", "day": "11", "time": "08:15:05", "status": "Failed", "user": "test", "ip": "203.0.113.5"},
    ]
    flagged = {"203.0.113.5": 3}

    result = find_compromised(events, flagged)

    assert result == []


def test_find_compromised_ignores_login_before_failures():
    events = [
        {"month": "Nov", "day": "11", "time": "10:00:00", "status": "Accepted", "user": "zee", "ip": "192.168.1.10"},
        {"month": "Nov", "day": "11", "time": "10:05:01", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
        {"month": "Nov", "day": "11", "time": "10:05:03", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
        {"month": "Nov", "day": "11", "time": "10:05:05", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
    ]
    flagged = {"192.168.1.10": 3}

    result = find_compromised(events, flagged)

    assert result == []

def test_find_brute_force_ips_flags_three_failures_within_window():
    events = [
        {"month": "Nov", "day": "11", "time": "08:15:01", "status": "Failed", "user": "root", "ip": "203.0.113.5"},
        {"month": "Nov", "day": "11", "time": "08:15:03", "status": "Failed", "user": "admin", "ip": "203.0.113.5"},
        {"month": "Nov", "day": "11", "time": "08:15:05", "status": "Failed", "user": "test", "ip": "203.0.113.5"},
    ]

    result = find_brute_force_ips(events)

    assert "203.0.113.5" in result
    assert result["203.0.113.5"] == 3


def test_find_brute_force_ips_ignores_failures_spread_out():
    events = [
        {"month": "Nov", "day": "11", "time": "10:00:00", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
        {"month": "Nov", "day": "11", "time": "10:02:00", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
        {"month": "Nov", "day": "11", "time": "10:04:00", "status": "Failed", "user": "zee", "ip": "192.168.1.10"},
    ]

    result = find_brute_force_ips(events)

    assert result == {}

def test_find_targeted_usernames_collects_failed_usernames_only():
    events = [
        {"month": "Nov", "day": "11", "time": "09:02:17", "status": "Failed", "user": "oracle", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:19", "status": "Failed", "user": "postgres", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:21", "status": "Failed", "user": "root", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:02:25", "status": "Accepted", "user": "admin", "ip": "198.51.100.77"},
        {"month": "Nov", "day": "11", "time": "09:03:00", "status": "Failed", "user": "ubuntu", "ip": "10.0.0.9"},
    ]
    flagged = {"198.51.100.77": 3}

    result = find_targeted_usernames(events, flagged)

    assert result["198.51.100.77"] == {"oracle", "postgres", "root"}
    assert "10.0.0.9" not in result
