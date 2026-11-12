import re
from collections import Counter

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
            


if __name__ == "__main__":
    events = load_events("sample_auth.log")
    print(f"Parsed {len(events)} events")
    for ip, count in count_failures_by_ip(events).most_common():
        print(ip, count)
    