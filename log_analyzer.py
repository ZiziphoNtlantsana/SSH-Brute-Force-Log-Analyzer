import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"(?P<status>Failed|Accepted)\s+password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def parse_line(line):
    match = LOG_PATTERN.search(line)
    if not match:
        return None
    return match.groupdict()
def load_events(path):
    events= []
    with open(path) as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return  events

def count_failures_by_ip(events):
    return Counter(e["ip"] for e in events if e["status"]=="Failed") 

def event_time(event):
    text = f"2026 {event['month']} {event['day']} {event['time']}"
    return datetime.strptime(text, "%Y %b %d %H:%M:%S")


def find_brute_force_ips(events, threshold=3, window_seconds=60):
    failure_times = defaultdict(list)
    for e in events:
        if e["status"] == "Failed":
            failure_times[e["ip"]].append(event_time(e))

    window = timedelta(seconds=window_seconds)
    flagged = {}
    for ip, times in failure_times.items():
        times.sort()
        start = 0
        most_in_window = 0
        for end in range(len(times)):
            while times[end] - times[start] > window:
                start += 1
            most_in_window = max(most_in_window, end - start + 1)
        if most_in_window >= threshold:
            flagged[ip] = most_in_window
    return flagged


def find_compromised(events, flagged):
    failed_seen = set()
    compromised = []
    for e in events:
        ip = e["ip"]
        if ip not in flagged:
            continue
        if e["status"] == "Failed":
            failed_seen.add(ip)
        elif e["status"] == "Accepted" and ip in failed_seen:
            compromised.append({"ip": ip, "user": e["user"], "time": e["time"]}) 
    return compromised

def find_targeted_usernames(events, flagged):
    targeted = defaultdict(set)

    for e in events:
            ip = e["ip"]
            if ip not in flagged:
                continue

            if e["status"] == "Failed":
                targeted[ip].add(e["user"])
    return targeted

    
  

if __name__ == "__main__":
    events = load_events("sample_auth.log")
    print(f"Parsed {len(events)} events")
    print("Flagged IPs (3+ failures within 60 seconds):")
    for ip, count in find_brute_force_ips(events).items():
        print(ip, count)
    flagged = find_brute_force_ips(events)
    print("Compromised logins:")
    for c in find_compromised(events, flagged):
        print(c)
    print("Usernames targeted:")
    for ip, users in find_targeted_usernames(events, flagged).items():
        print(ip, sorted(users))


            


    