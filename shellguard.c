#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <seccomp.h>

#define MAX_RULES 128
#define MAX_LINE 256

typedef struct {
    char syscall_name[64];
    int allow; // 1 = ALLOW, 0 = DENY
} Rule;

int load_policy(const char *filename, Rule *rules, int max_rules) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        perror("policy file open failed");
        exit(1);
    }

    char line[MAX_LINE];
    int count = 0;

    while (fgets(line, sizeof(line), f) && count < max_rules) {
        if (line[0] == '#' || line[0] == '\n' || line[0] == ' ') continue;

        char action[16], syscall_name[64];
        if (sscanf(line, "%15s %63s", action, syscall_name) == 2) {
            strncpy(rules[count].syscall_name, syscall_name, 63);
            rules[count].allow = (strcmp(action, "ALLOW") == 0) ? 1 : 0;
            count++;
        }
    }

    fclose(f);
    return count;
}

void apply_seccomp(Rule *rules, int count) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        fprintf(stderr, "seccomp_init failed\n");
        exit(1);
    }

    for (int i = 0; i < count; i++) {
        if (rules[i].allow) {
            int syscall_num = seccomp_syscall_resolve_name(rules[i].syscall_name);
            if (syscall_num == __NR_SCMP_ERROR) {
                fprintf(stderr, "Unknown syscall: %s (skipped)\n", rules[i].syscall_name);
                continue;
            }
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_num, 0);
        }
    }

    if (seccomp_load(ctx) != 0) {
        fprintf(stderr, "seccomp_load failed\n");
        exit(1);
    }

    seccomp_release(ctx);
}

void log_result(const char *program, int status) {
    FILE *log = fopen("shellguard.log", "a");
    if (!log) return;

    if (WIFEXITED(status)) {
        fprintf(log, "[%s] Exited normally, code=%d\n", program, WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        fprintf(log, "[%s] KILLED by signal %d (%s)\n", program, WTERMSIG(status), strsignal(WTERMSIG(status)));
    }

    fclose(log);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <policy_file> <program> [args...]\n", argv[0]);
        return 1;
    }

    char *policy_file = argv[1];
    char **target_argv = &argv[2];

    Rule rules[MAX_RULES];
    int rule_count = load_policy(policy_file, rules, MAX_RULES);

    printf("[shellguard] %d policy rules loaded\n", rule_count);
    printf("[shellguard] running '%s' in sandbox...\n", target_argv[0]);

    pid_t pid = fork();

    if (pid == 0) {
        apply_seccomp(rules, rule_count);
        execvp(target_argv[0], target_argv);
        perror("execvp failed");
        _exit(127);

    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            printf("[shellguard] process exited normally, code: %d\n", WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            printf("[shellguard] process KILLED by signal %d (%s) -- likely seccomp violation\n",
                   WTERMSIG(status), strsignal(WTERMSIG(status)));
        }

        log_result(target_argv[0], status);

    } else {
        perror("fork failed");
        return 1;
    }

    return 0;
}
