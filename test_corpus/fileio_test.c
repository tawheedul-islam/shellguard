#include <stdio.h>
int main() {
    FILE *f = fopen("output.txt", "w");
    fprintf(f, "Hello from fileio test\n");
    fclose(f);
    printf("File write successful\n");
    return 0;
}
