/* CSCI 4178 workshop source. INSTRUCTOR ONLY: never distribute this file.
 *
 * Derived from the 2025 re-hands-on scrambler. The 2025 version reversed the
 * line and flipped alphabetic case, which left the output readable: the
 * scrambled file could be solved by eye with no tools at all. The case flip is
 * replaced here by a single XOR constant, so the output is opaque while the
 * exercise stays at exactly two operations: one on position, one on value.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define KEY 0x5A

int main(void) {
    char buf[256];
    FILE *in, *out;

    in = fopen("message.txt", "r");
    if (in == NULL) {
        perror("message.txt");
        return 1;
    }

    out = fopen("message.scr", "wb");
    if (out == NULL) {
        perror("message.scr");
        fclose(in);
        return 1;
    }

    if (fgets(buf, sizeof(buf), in) == NULL) {
        fprintf(stderr, "Error: could not read message.\n");
        fclose(in);
        fclose(out);
        return 1;
    }

    /* Remove trailing newline if present */
    buf[strcspn(buf, "\n")] = '\0';

    int len = (int)strlen(buf);

    /* Step 1: reverse the characters in place */
    for (int i = 0; i < len / 2; i++) {
        char tmp = buf[i];
        buf[i] = buf[len - 1 - i];
        buf[len - 1 - i] = tmp;
    }

    /* Step 2: mask every byte */
    for (int i = 0; i < len; i++) {
        buf[i] = (char)(buf[i] ^ KEY);
    }

    fwrite(buf, 1, len, out);

    fclose(in);
    fclose(out);
    return 0;
}
