#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <openssl/evp.h>
#include <ctype.h>
#include <asm/page.h>

#include "xcrypt.h"

/* salt comes from CEPH_AES_IV */
const char *salt = "cephsageyudagreg";

void disp_usage()
{   
	puts("usage:");
#ifdef EXTRA_CREDIT
	puts("xcipher {-e|-d} [-c CIPHER] [-l keylen] [-u block size] "); 
	puts("       [-h] -p PASSWORD infile outfile");
#else
	puts("xcipher {-e|-d} [-h] -p PASSWORD infile outfile");
#endif
	puts("-e:  to encrypt;");
	puts("-d:  to decrypt;");
#ifdef EXTRA_CREDIT
	puts("-c:  to specify the type of the cipher;");
	puts("-l:  to specify the length of the key [64,448];");
	puts("     if specify the length with non-default value in encryption,");
	puts("     specify that length in decryption");
	puts("     default:128");
	puts("-u:  to specify the size of the block [8,4096];");
	puts("     default:PAGE_SIZE");
#endif
	puts("-p:  to specify the password;");
	puts("-h:  to display this message;");
	puts("infile:  input file name;");
	puts("outfile: output file name;");
}

void set_default(struct cipher_vec *args)
{
	args->key = NULL;
	args->infile = NULL;
	args->outfile = NULL;
	args->keylen = DEFAULT_KEY_LEN;
	args->flag = -1;
#ifdef EXTRA_CREDIT
	args->cipher_type = 0;
	args->blk_size = DEFAULT_BLK_SIZE;
#endif
}

#ifdef EXTRA_CREDIT
int find_cipher(char *name)
{
	int i = -1,j;
	char cipher[20];
	strcpy(cipher, "cbc(");
	strcat(cipher, name);
	strcat(cipher, ")");
	for (j=0; j < (sizeof(cipher_opt)/sizeof(char *)); j++) {
		if (strcmp(cipher, cipher_opt[j]) == 0) {
			i = j;
			break;
		}
	}    
	return i;
}

int check_keylen_blksize(int cipher_type, int keylen, int blksize)
{
    /**
     * key length options come from descriptions
     * of each cipher in wikipedia
     */
    if (blksize < MIN_BLK_SIZE || blksize > MAX_BLK_SIZE)
	return -1;
    
    switch (cipher_type) {
	case 0:/* aes */
	    if ((keylen == 16 || keylen == 24 || keylen == 32)
		&& (blksize % 16 == 0))
		return 0;
	    else
		return -1;
	case 1:/* blowfish */
	    if ((keylen >= 4 && keylen <= 56) && (blksize % 8 == 0))
		return 0;
	    else
		return -1;
	case 2:/* twofish */
	    if ((keylen == 16 || keylen == 24 || keylen == 32)
		&& (blksize % 16 == 0))
		return 0;
	    else
		return -1;
	case 3:/* anubis */
	    if ((keylen >= 16) && (keylen <= 40) && (keylen%4 == 0)
		&& (blksize % 16 == 0))
		return 0;
	    else
		return -1;
	/* have not found out how to make those three work
	case 4:
	    if ((keylen == 8) && (blksize == 8))
		return 0;
	    else
	     	return -1;
	case 5: 
	    if ((keylen == 16 || keylen == 24 || keylen == 8)
	     	&& (blksize == 8))
	     	return 0;
	    else
	     	return -1;
	case 6: 
	     if ((keylen == 16 || keylen == 24 || keylen == 32)
	     	&& (blksize == 16))
	     	return 0;
	     else
	     	return -1;
    	*/
	default:
	    return 0;
    }
}
#endif
void filter_copy(char **result, const char *src, char c)
{
	char *temp = (char *)malloc(strlen(src)+1);
	int i,j;  
	for (i = 0, j = 0; src[i] != '\0'; i++)  
	{  
		if (src[i] != c)  
			temp[j++] = src[i];  
        }
    	temp[j] = '\0';
	*result = (char *)malloc(strlen(temp)+1);
	strcpy(*result, temp);
	free(temp);
}

int main(int argc, char *argv[])
{
	struct cipher_vec args_vec;
	char *userkey = NULL;

	int opt = 0;

#ifdef EXTRA_CREDIT
	const char *optstring = "p:c:l:u:edh";
#else
	const char *optstring = "p:edh";
#endif

	int args_num = 6;
	char ch;

	set_default(&args_vec);

	if (argc < args_num) {
		puts("wrong argument(s):too few arguments");
		disp_usage();
		return -1;
	}
	while ((opt = getopt(argc, argv, optstring)) != -1)
	{
		switch (opt) {
		case 'p':
			/* remove the '\n' from password */
			filter_copy(&userkey, optarg, '\n');
			break;
		case 'e':
			if (args_vec.flag != -1) {
				puts("wrong argument(s): encrypt or decrypt");
				disp_usage();
				return -1;
			}
			args_vec.flag = ENCRYPT;
			break;
		case 'd':
			if (args_vec.flag != -1) {
				puts("wrong argument(s): encrypt or decrypt");
				disp_usage();
				return -1;
			}
			args_vec.flag = DECRYPT;
			break;

#ifdef EXTRA_CREDIT
		case 'c':
			args_vec.cipher_type = find_cipher(optarg);
			if (args_vec.cipher_type == -1){
				puts("cipher not supported");
				return -1;
			}
			break;
		case 'l':
			args_vec.keylen = atoi(optarg)/8;
			break;
		case 'u':
			args_vec.blk_size = atoi(optarg);
			break;
#endif
		case 'h':
		case '?':
			disp_usage();
			return 0;
		default:
                /* You won't actually get here. */
			break;
		}
	}
	if (args_vec.flag == -1) {
		puts("wrong argument(s): encrypt or decrypt");
		disp_usage();
		return -1;
	}
	args_vec.infile = argv[optind++];
	args_vec.outfile = argv[optind];

	if (userkey == NULL) {
		puts("wrong argument(s): null key");
		return -1;
	}
	if(args_vec.infile == NULL){
		puts("wrong argument(s): null infile");
		return -1;
	}
	if(args_vec.outfile == NULL){
		puts("wrong argument(s): null outfile");
		return -1;
	}

#ifdef EXTRA_CREDIT
	if (check_keylen_blksize(args_vec.cipher_type, 
				 args_vec.keylen, args_vec.blk_size) != 0 ) {
		puts("wrong key length or/and block size.");
		return -1;
	}
#endif

	args_vec.key = malloc(sizeof(args_vec.keylen));
	if (!args_vec.key) {
		puts("failed to generate key.");
		return -1;
	}
	/* hash the password to get the key with length of keylen */
	if(PKCS5_PBKDF2_HMAC_SHA1((void *)userkey, strlen(userkey), 
                              (void *)salt, strlen(salt), 10000,
                              args_vec.keylen, (void *)args_vec.key) != 1) {
		puts("failed to generate key.");
		return -1;
	}

	if (access(args_vec.infile, F_OK) != 0) {
		printf("No such file \"%s\"\n", args_vec.infile);
		return -1;
	}

	if (access(args_vec.outfile, F_OK) == 0) {
		printf("Overwrite existing file \"%s\"? (y or n) ", args_vec.outfile);
		ch = getchar();
		if (tolower(ch) != 'y') {
			return 0;
		}
	}

	errno = 0;
	if(syscall(__NR_xcrypt, &args_vec)) {
	    /* EDOM means e/dcryption failed, other error msgs are shown by perror */
	    if (errno == -EDOM)
		puts("xcrypt: en/decryption failed");
	    else perror("xcrypt");
	}
	return 0;
}	
