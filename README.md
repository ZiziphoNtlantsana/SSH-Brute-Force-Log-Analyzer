# SSH Brute-Force Log Analyzer

A tool I built in Python that reads SSH login logs and shows who is attacking a server, which usernames they tried, and whether any of them got in.

## What it does

Every server that's open to the internet gets hit with automated login attempts all day. Most of them fail, but one successful login after a lot of failures is exactly what a SOC analyst needs to catch. This tool finds those patterns in an `auth.log` file and puts them in one clear report.

It checks for:

* Brute-force attempts: 3 or more failed logins from the same IP within 60 seconds
* The usernames each attacker tried (`root`, `admin`, `oracle` and so on)
* Compromised logins: an IP that failed repeatedly and then logged in successfully
* IPs that only look suspicious but never got in, so they're flagged as brute-force attempts, not as compromised

## Try it

```
python log_analyzer.py
```

It reads `sample_auth.log` and prints a report like this:

```
IP Address: 198.51.100.77
Failed attempts in window: 4
Targeted usernames: oracle, postgres, root
Status: COMPROMISED
Successful login username: root
Successful login timestamp: 09:02:25
```

## Run the tests
```
pip install pytest
py -m pytest -v
```

## Why I built this

I'm working towards a SOC Analyst role, so I wanted to build the kind of detection I'd be doing on the job. The part that took me the longest was the 60-second window, because counting failures isn't enough. The time between them matters too. It's also fully tested, with 6 automated checks confirming the logic works correctly, including the cases where it should not raise an alarm.
