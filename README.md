# FileRun Brute Force

A simple threaded, resumable brute-forcing utility for FileRun login endpoints.
Supports username brute (username wordlist + single password), password brute (single username + password wordlist), or full combo. Detects common JSON responses (invalid username / invalid password / account deactivated / possible valid). Two output modes: `verbose` and `silent` (spinner + minimal output). Includes pause & resume via a session file.

---

## Features

* Username, password, or combination brute-force modes
* Threaded using `concurrent.futures.ThreadPoolExecutor` (customizable with `-t`)
* Range selection for wordlists (choose start/end lines)
* Pause (CTRL+C) and resume session (`.bf_filerun_session.json`)
* Response-aware decision logic
* Output modes:

  * `-v` / `--verbose` — full per-request output
  * `-s` / `--silent` — spinner and minimal output (only important events)
---

## Requirements

* Python 3.8+ (or newer)
* pip
* Python packages:

  * `requests`
  * `termcolor`

Install dependencies:

```bash
python3 -m pip install requests termcolor
```

Or create `requirements.txt`:

```
requests
termcolor
```

and install:

```bash
python3 -m pip install -r requirements.txt
```

---

## Quick usage / examples

Show help / usage banner:

```bash
python3 run.py
```

### 1) Brute-force usernames (username wordlist + single password)

```bash
python3 run.py -u http://target.com/ -L usernames.txt -p MyKnownPassword -t 100 -v
```

When running this, if a response contains `"error":"Invalid password."` the tool treats that username as **valid** (password is wrong). Those usernames will be listed at the end — useful for a follow-up password brute.

### 2) Brute-force passwords (single username + password wordlist)

Verbose output (full):

```bash
python3 run.py -u http://target.com/ -l superuser -P /usr/share/wordlists/rockyou.txt -t 100 -v
```

Silent mode (spinner + minimal messages):

```bash
python3 run.py -u http://target.com/ -l superuser -P /usr/share/wordlists/rockyou.txt -t 100 -s
```

### 3) Combo mode (both lists)

```bash
python3 run.py -u http://target.com/ -L usernames.txt -P passwords.txt -t 200 -v
```
---

## Wordlist range selection

When a wordlist is provided the script will prompt:

```
[!] Password wordlist contains 14344385 lines
[?] Enter custom range (y=all, e.g. 1-200):
```

Examples of accepted input:

* Enter or `y` → use full file
* `1-7000` → use lines 1 through 7000
* `200` → use lines 1 through 200

Line numbers are 1-based; output includes `[line: N]` so you can track progress precisely.

---

## Pause & Resume

* Press `CTRL+C` while the program is running. You will be prompted:

  * Save session (pause) — script writes `.bf_filerun_session.json` with progress
  * Exit — no save (or keep existing session)
* To resume a saved session, run the script without arguments (or run and agree to resume when prompted). The tool will read the session and continue from the last saved line.

Session file: `.bf_filerun_session.json` (in the current working directory)

---

## Safety, ethics & legal notice

This tool is intended for authorized security testing and educational use only.

**Do not** run this tool against systems you do not own or do not have explicit written permission to test. Unauthorized access attempts are illegal and unethical.

By using this tool you confirm that you have permission to test the target(s) and that you will comply with all applicable laws, policies, and regulations.

Include an explicit permission letter / scope when conducting engagements and limit impact (start with small thread counts, obtain backups, coordinate with defenders).

---

## Contributing & improvements

If you publish on GitHub, consider adding:

* Tests for the parsing logic (mocked HTTP responses)
* CI for linting and basic smoke tests
* Optional features: proxy support, rate limiting, per-thread proxies, output logging to CSV/JSON, streaming very large wordlists (no full file load)
* Better session format that stores progress per (username,password) combination for combo-mode resume

If you want, I can also:

* generate a `README.md` file ready to push (this file) — done
* produce a `LICENSE` (MIT) file
* produce an example `requirements.txt`
* open-source friendly `setup.py` or `pyproject.toml`
