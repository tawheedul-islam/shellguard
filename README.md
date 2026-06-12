# ShellGuard: Syscall Sandbox with seccomp-BPF

A CLI tool that runs a target program in a sandbox by allowing/denying
syscalls based on a policy file, using Linux seccomp-BPF.

## Build
gcc shellguard.c -o shellguard -lseccomp

## Usage
./shellguard policy.txt ./program [args...]
