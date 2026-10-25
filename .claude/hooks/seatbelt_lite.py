#!/usr/bin/env python3
"""Agent Seatbelt Lite: a Claude Code PreToolUse hook that blocks a few catastrophic actions.

Blocks (deny, with a reason Claude can read):
  rm-catastrophic     rm -r / rm -rf on /, /*, ~, ~/..., $HOME, or a top-level system dir
  git-force-protected git push --force / -f / --force-with-lease / +refspec to main, master, prod(uction),
                      release, including a bare `git push -f` while that branch is checked out
  pipe-to-shell       curl ... | sh / bash / zsh (also wget -O-)
  read-env-file       cat/less/head/tail/... of a .env file, or the Read/Grep tool on one
                      (.env.example / .env.sample / .env.template are allowed)

Everything else is allowed silently. Stdlib only, Python 3.8+. MIT license.
Full version (60+ rules, ask-before-run, Cursor support, config, installer):
https://humaki.gumroad.com/l/agent-seatbelt
"""
import json
import os
import re
import shlex
import subprocess
import sys

PROTECTED_BRANCHES = {"main", "master", "production", "prod", "release"}
SYSTEM_DIRS = {"/", "/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/opt", "/private", "/root",
               "/sbin", "/System", "/Users", "/usr", "/var", "/Library", "/Applications"}
WRAPPERS = {"sudo", "env", "nohup", "time", "command", "builtin", "exec", "nice", "doas"}
READERS = {"cat", "less", "more", "head", "tail", "bat", "nl", "strings", "xxd", "od", "tac",
           "grep", "rg", "awk", "sed", "cut", "sort", "base64", "cp", "scp", "source", "."}
SAFE_ENV_SUFFIXES = (".example", ".sample", ".template", ".dist")
SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}

_SPLIT = re.compile(r"\s*(?:&&|\|\||;|\n)\s*")


def segments(command):
    """Split on && || ; and newlines (outside quotes). Pipes are kept, rules look at them."""
    out, buf, q = [], [], None
    i = 0
    while i < len(command):
        c = command[i]
        if q:
            buf.append(c)
            if c == q:
                q = None
            i += 1
            continue
        if c in "'\"":
            q = c
            buf.append(c)
            i += 1
            continue
        m = _SPLIT.match(command, i)
        if m and m.end() > i:
            out.append("".join(buf))
            buf = []
            i = m.end()
            continue
        buf.append(c)
        i += 1
    out.append("".join(buf))
    return [s.strip() for s in out if s.strip()]


def tokens(segment):
    try:
        t = shlex.split(segment)
    except ValueError:
        t = segment.split()
    while t and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", t[0]) or os.path.basename(t[0]) in WRAPPERS):
        t.pop(0)
        while t and t[0].startswith("-"):
            t.pop(0)
    return t


def is_env_file(path):
    name = os.path.basename(path.strip("'\""))
    if not (name == ".env" or name.startswith(".env.") or name.endswith(".env")):
        return False
    return not name.endswith(SAFE_ENV_SUFFIXES)


def check_rm(t):
    if not t or os.path.basename(t[0]) != "rm":
        return None
    flags = "".join(a[1:] for a in t[1:] if a.startswith("-") and not a.startswith("--"))
    recursive = "r" in flags or "R" in flags or "--recursive" in t
    if not recursive:
        return None
    for a in t[1:]:
        if a.startswith("-"):
            continue
        p = a.rstrip("/") or "/"
        if p in ("~", "$HOME", "${HOME}") or a in ("/*", "~/*", "$HOME/*") or p in SYSTEM_DIRS:
            return ("rm-catastrophic", f"`rm -r {a}` would delete your home folder or a system directory.")
        if re.match(r"^(~|\$HOME|\$\{HOME\})/[^/]+$", p):
            return ("rm-catastrophic", f"`rm -r {a}` deletes a top-level folder in your home directory.")
    return None


def current_branch(cwd):
    try:
        out = subprocess.run(["git", "symbolic-ref", "--quiet", "--short", "HEAD"], cwd=cwd or None,
                             capture_output=True, text=True, timeout=3)
        return out.stdout.strip() if out.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def check_git(t, cwd=""):
    if len(t) < 2 or os.path.basename(t[0]) != "git":
        return None
    args = t[1:]
    while args and args[0] in ("-C", "-c"):  # git -C dir / -c k=v
        args = args[2:]
    if not args or args[0] != "push":
        return None
    rest = args[1:]
    force = any(a in ("-f", "--force") or a.startswith("--force-with-lease") or
                (a.startswith("-") and not a.startswith("--") and "f" in a) for a in rest)
    refs = [a for a in rest if not a.startswith("-")]
    targets = []
    for r in refs[1:]:  # refs[0] is the remote
        plus = r.startswith("+")
        dst = r.lstrip("+").split(":")[-1].replace("refs/heads/", "")
        targets.append((dst, plus))
    if force and len(refs) <= 1:  # `git push -f` / `git push -f origin`: pushes the current branch
        targets.append((current_branch(cwd), False))
    for dst, plus in targets:
        if dst in PROTECTED_BRANCHES and (force or plus):
            return ("git-force-protected", f"Force-pushing to `{dst}` rewrites shared history. Push a branch and open a PR.")
    return None


def check_pipe_to_shell(segment):
    parts = [p.strip() for p in re.split(r"(?<!\|)\|(?!\|)", segment)]
    if len(parts) < 2:
        return None
    first = tokens(parts[0])
    if not first or os.path.basename(first[0]) not in ("curl", "wget"):
        return None
    for p in parts[1:]:
        t = tokens(p)
        if t and os.path.basename(t[0]) in SHELLS:
            return ("pipe-to-shell", "Piping a download straight into a shell runs unreviewed code. "
                                     "Download it, read it, then run it.")
    return None


def check_env_read(t):
    if not t or os.path.basename(t[0]) not in READERS:
        return None
    for a in t[1:]:
        if not a.startswith("-") and is_env_file(a):
            return ("read-env-file", f"`{a}` holds secrets. Read `.env.example`, or ask the user for the value you need.")
    return None


def nested_command(t):
    """`bash -c "..."`, `sh -lc '...'` or `eval ...`: return the inner command string."""
    if not t:
        return None
    name = os.path.basename(t[0])
    if name == "eval" and len(t) > 1:
        return " ".join(t[1:])
    if name in SHELLS:
        for i, a in enumerate(t[1:-1], start=1):
            if a.startswith("-") and not a.startswith("--") and "c" in a:
                return t[i + 1]
    return None


def check_command(command, cwd="", depth=0):
    if depth > 3:
        return None
    for seg in segments(command):
        r = check_pipe_to_shell(seg)
        if r:
            return r
        for part in re.split(r"(?<!\|)\|(?!\|)", seg):
            t = tokens(part)
            inner = nested_command(t)
            r = (check_command(inner, cwd, depth + 1) if inner else None) or \
                check_rm(t) or check_git(t, cwd) or check_env_read(t)
            if r:
                return r
    return None


def evaluate(payload):
    tool = payload.get("tool_name", "")
    ti = payload.get("tool_input") or {}
    if tool == "Bash":
        return check_command(ti.get("command", ""), payload.get("cwd", ""))
    if tool in ("Read", "Grep"):
        path = ti.get("file_path") or ti.get("path") or ""
        if path and is_env_file(path):
            return ("read-env-file", f"`{path}` holds secrets. Read `.env.example`, or ask the user for the value you need.")
    return None


def main():
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        result = evaluate(payload)
    except Exception as exc:  # never break the agent because of a bug here
        sys.stderr.write(f"[seatbelt-lite] internal error, allowing: {exc}\n")
        return 0
    if result:
        rule, reason = result
        print(json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": f"[seatbelt-lite:{rule}] {reason}",
        }}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
