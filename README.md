# ShellGuard: Syscall Sandbox with seccomp-BPF

A CLI tool that runs a target program inside a sandbox by allowing or
denying Linux syscalls based on a user-defined policy file, using
seccomp-BPF (libseccomp).

## CSE3104 - Operating System Lab Project

## Features
- Reads a simple ALLOW/DENY policy file
- Applies a seccomp-BPF filter to a forked child process
- Runs the target program (`execvp`) inside the sandbox
- Reports whether the process exited normally or was killed
  (SIGSYS) due to a denied syscall
- Logs every run's result to `shellguard.log`

## Build

```bash
gcc shellguard.c -o shellguard -lseccomp
```

## Usage

```bash
./shellguard <policy_file> <program> [args...]
```

Examples:
```bash
./shellguard policy.txt ./benign.sh
./shellguard policy.txt ./malicious.sh
./shellguard policy_strict.txt ./test_corpus/fork_test
```

## Policy File Format

Each line is either a comment (starting with `#`) or a rule:
ALLOW <syscall_name>

DENY  <syscall_name>

- Syscalls not listed (or explicitly DENY) result in the process
  being killed with SIGSYS (signal 31) when attempted.
- `policy.txt` contains the syscalls required to run a normal bash
  script, with `socket`/`connect`/`ptrace` denied (used to block
  network access by `malicious.sh`).
- `policy_strict.txt` additionally denies `clone`/`fork`, used to
  demonstrate blocking process creation (`test_corpus/fork_test`).

## Project Structure
shellguard.c          - main tool (policy parser + seccomp enforcement)

policy.txt            - default policy (bash-compatible, network denied)

policy_strict.txt     - strict policy (also denies fork/clone)

benign.sh             - safe test script

malicious.sh          - test script attempting network access via curl

test_corpus/          - C programs exercising specific syscalls

fileio_test.c       - file read/write

fork_test.c         - fork()/clone()

test1.c               - minimal standalone seccomp demo

shellguard.log        - run history log (generated at runtime)

report/               - LaTeX project report

## Test Results Summary

| Test | Policy | Result |
|---|---|---|
| benign.sh | policy.txt | Exited normally (code 0) |
| malicious.sh (curl) | policy.txt | Killed by SIGSYS (network denied) |
| test_corpus/fileio_test | policy.txt | Exited normally (code 0) |
| test_corpus/fork_test | policy.txt | Exited normally (clone allowed) |
| test_corpus/fork_test | policy_strict.txt | Killed by SIGSYS (clone denied) |

## Verification with strace

```bash
strace -f ./shellguard policy.txt ./malicious.sh 2>&1 | grep -iE "sigsys|seccomp|bad system call"
```
