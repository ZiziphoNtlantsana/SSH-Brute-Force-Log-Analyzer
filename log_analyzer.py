import re

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


if __name__ == "__main__":
    with open("sample_auth.log") as f:
        for line in f:
            print(parse_line(line))