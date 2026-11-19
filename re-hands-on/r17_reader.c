#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Instructor source. Do not include in the student package. */
int main(int argc, char **argv) {
    uint8_t file[128];
    uint8_t plain[96];
    size_t n;
    unsigned int length;
    uint8_t sum = 0;
    unsigned int plain_sum = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s FILE\n", argv[0]);
        return 2;
    }

    FILE *in = fopen(argv[1], "rb");
    if (in == NULL) {
        perror(argv[1]);
        return 2;
    }
    n = fread(file, 1, sizeof file, in);
    if (ferror(in) || !feof(in)) {
        fprintf(stderr, "Could not read complete file\n");
        fclose(in);
        return 2;
    }
    fclose(in);

    if (n < 7 || memcmp(file, "R4178", 5) != 0) {
        fprintf(stderr, "Invalid header\n");
        return 1;
    }
    length = file[5];
    if (length == 0 || length > 80 || n != (size_t)length + 7) {
        fprintf(stderr, "Invalid length\n");
        return 1;
    }

    for (unsigned int i = 0; i < length; i++) {
        sum = (uint8_t)(sum + file[6 + i]);
    }
    if (sum != file[6 + length]) {
        fprintf(stderr, "Invalid checksum\n");
        return 1;
    }

    for (unsigned int i = 0; i < length; i++) {
        plain[length - 1 - i] =
            (uint8_t)(file[6 + i] ^ (uint8_t)(0x23 + (i % 5)));
    }
    plain[length] = 0;
    for (unsigned int i = 0; i < length; i++) {
        plain_sum += plain[i];
    }
    printf("Accepted: %u characters; character sum=%u\n", length, plain_sum);
    return 0;
}
