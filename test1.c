#include <stdio.h>
#include <seccomp.h>
#include <unistd.h>

int main() {
    scmp_filter_ctx ctx;

    ctx = seccomp_init(SCMP_ACT_KILL);

    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(rt_sigreturn), 0);

    seccomp_load(ctx);

    printf("Hello! ei line print hobe karon write allow\n");

    FILE *f = fopen("test.txt", "r");
    if (f) {
        printf("File open hoyeche (eta print howar kotha na)\n");
        fclose(f);
    } else {
        printf("Eita print hobe na, openat e killed hoye jabo\n");
    }

    return 0;
}
