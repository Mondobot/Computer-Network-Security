#include <openssl/sha.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/* hashing modes */
#define MODE_NORMAL 1
#define MODE_REVERSED 2

#define DATA_MAX_BUF 512

static int mode = MODE_NORMAL;

unsigned char* alloc_hash() {
    unsigned char *hash = malloc(SHA_DIGEST_LENGTH);
    if (hash == NULL) {
        fprintf(stderr, "Malloc failed.\n");
        exit(EXIT_FAILURE);
    }

    return hash;
}

unsigned char* reverse_hash(unsigned char *old_hash) {
    int i, j;
    unsigned char *hash = alloc_hash();

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        j = SHA_DIGEST_LENGTH - i - 1;
        hash[j] = old_hash[i];
    }

    return hash;
}

unsigned char* compute_hash(char *buf, unsigned int len) {
    unsigned char *hash = alloc_hash();

    printf("Computing hash for %d bytes.\n", len);

    memset(hash, 0, SHA_DIGEST_LENGTH);
    SHA1((unsigned char*)buf, len, hash);

    return hash;
}

void toggle_mode(int signal) {
    if (mode == MODE_NORMAL) {
        mode = MODE_REVERSED;
    } else {
        mode = MODE_NORMAL;
    }
}

unsigned int read_data(char *dst) {
    int r;

    r = fread(dst, 1, DATA_MAX_BUF, stdin);
    if (ferror(stdin)) {
        fprintf(stderr, "Error while reading input.\n");
        exit(EXIT_FAILURE);
    }

    printf("\nRead %d bytes from input.\n", r);

    return r;
}

void print_hash(unsigned char* hash) {
    int i;

    for (i = 0; i < SHA_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
}

int main() {
    unsigned int len;
    char data_buf[DATA_MAX_BUF];
    unsigned char *hash, *rev_hash;

    printf("---------------------------------------------------------------\n");
    printf("Hi! I'm the L33T HASHER.\n\n");
    printf("If you send me a signal before I finish making the normal hash, \n"
           "I will also give you a special hash!\n");
    printf("---------------------------------------------------------------\n");
    printf("What would you like me to hash?\n");
    printf("Input data (max %d bytes): ", DATA_MAX_BUF);

    memset(data_buf, 0, sizeof(data_buf));
    len = read_data(data_buf);

    if (signal(SIGUSR1, toggle_mode) == SIG_ERR) {
        fputs("An error occurred while setting a signal handler.\n", stderr);
        return EXIT_FAILURE;
    }

    hash = compute_hash(data_buf, len);
    
    printf("     NORMAL HASH: ");
    print_hash(hash);
    printf("\n");

    if (mode == MODE_REVERSED) {
        rev_hash = reverse_hash(hash);
        printf("    SPECIAL HASH: ");
        print_hash(rev_hash);
        printf("\n");
    }

    return 0;
}
