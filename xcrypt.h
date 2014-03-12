/*
 header for both system call and user level program
 */

#ifndef XCRYPT_H
#define XCRYPT_H

#define EXTRA_CREDIT

#define __NR_xcrypt 349

#define ENCRYPT 1
#define DECRYPT 0

#define DEFAULT_KEY_LEN 16
#define DEFAULT_BLK_SIZE PAGE_SIZE

struct cipher_vec {
    char *key;
    char *infile;
    char *outfile;
    int flag;
    int keylen;
#ifdef EXTRA_CREDIT
    int cipher_type;
    int blk_size;
#endif
};

#ifdef EXTRA_CREDIT

#define MIN_BLK_SIZE 8
#define MAX_BLK_SIZE PAGE_SIZE

static char *cipher_opt[] = {
    "cbc(aes)",
    "cbc(blowfish)",
    "cbc(twofish)",
    "cbc(anubis)",
    /* have not found out how to make those three work
    "cbc(des)",
    "cbc(des3_ede)",
    "cbc(camellia)"
     */
};
#endif

#endif
