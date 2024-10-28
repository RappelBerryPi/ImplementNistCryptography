#include <stdio.h>

int main() {
    FILE *fp = fopen("../key.txt", "r");
    char line[100];
    char line2[12];
    fgets(line, 100, fp);
    printf("%s\n", line);
    fclose(fp);
    fgets(line2, 12, stdin);
}
