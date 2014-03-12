#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/crypto.h>
#include <crypto/md5.h>
#include <linux/scatterlist.h>

#include "xcrypt.h"

extern asmlinkage long (*xcryptfxn) (void *args);

MODULE_LICENSE("Dual BSD/GPL");

struct cipher_preamble {
	char check_key[MD5_DIGEST_SIZE];
#ifdef EXTRA_CREDIT
#define IV_SIZE 16
	char iv[IV_SIZE];
	int cipher_type;
	int blk_size;
#endif
};

#define PAD_SIZE 16
/* encryption and decryption come from the code
in net/ceph/crypto.c */
static int encrypt(struct blkcipher_desc *desc,
		void *dst, size_t *dst_len,
		const void *src, size_t src_len)
{
	struct scatterlist sg_in[2], sg_out[1];
	int ret = 0;
	size_t zero_padding = (0x10 - (src_len & 0x0f));
	char pad[PAD_SIZE];

	memset(pad, zero_padding, zero_padding);

	*dst_len = src_len + zero_padding;

	sg_init_table(sg_in, 2);
	sg_set_buf(&sg_in[0], src, src_len);
	sg_set_buf(&sg_in[1], pad, zero_padding);
	sg_init_table(sg_out, 1);
	sg_set_buf(sg_out, dst, *dst_len);

	ret = crypto_blkcipher_encrypt(desc, sg_out,
					sg_in, src_len + zero_padding);

	if (ret < 0)
		pr_err("xcrypt: encrypt failed %d\n", ret);

	return ret;
}

static int decrypt(struct blkcipher_desc *desc,
		void *dst, size_t *dst_len,
		const void *src, size_t src_len)
{
	struct scatterlist sg_in[1], sg_out[2];
	char pad[PAD_SIZE];
	int ret = 0;
	int last_byte;

	sg_init_table(sg_in, 1);
	sg_init_table(sg_out, 2);
	sg_set_buf(sg_in, src, src_len);
	sg_set_buf(&sg_out[0], dst, *dst_len);
	sg_set_buf(&sg_out[1], pad, sizeof(pad));

	ret = crypto_blkcipher_decrypt(desc, sg_out, sg_in, src_len);

	if (ret < 0) {
		pr_err("xcrypt: decrypt failed %d\n", ret);
		return ret;
	}

	if (src_len <= *dst_len)
		last_byte = ((char *)dst)[src_len - 1];
	else
		last_byte = pad[src_len - *dst_len - 1];
	if (last_byte <= 16 && src_len >= last_byte) {
		*dst_len = src_len - last_byte;
	} else {
		pr_err("xcrypt: decrypt got bad padding %d on src len %d\n",
			last_byte, (int)src_len);
		return -EPERM;  /* bad padding */
	}

	return ret;
}

#ifdef EXTRA_CREDIT

/*set the first 8 bytes of iv to be pagenum;
the second 8 bytes to be inode number;*/
static inline void set_iv(struct cipher_preamble *preamble, struct file *file)
{
	long long pagenum = ((int)&file + file->f_pos)>>10;
	memcpy(preamble->iv, &pagenum , sizeof(long long));
	memcpy(preamble->iv+8,
		&(file->f_dentry->d_inode->i_ino),
		sizeof(unsigned long));
}

/* module has to check keylen and blksize even if user-level also did */
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

static int set_preamble(const struct cipher_vec *kptr,
			struct cipher_preamble *preamble)
{
	struct hash_desc desc;
	struct scatterlist sg[1];
	int err = 0;
	struct crypto_hash *tfm = crypto_alloc_hash("md5", 0, CRYPTO_ALG_ASYNC);

	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto out_no_tfm;
	}
#ifdef EXTRA_CREDIT
	/* no need to hash the cipher type, because brute force works anyway. */
	preamble->cipher_type = kptr->cipher_type;
	/* plain text of blk_size shouldn't be a problem, I think */
	preamble->blk_size = kptr->blk_size;
#endif
	desc.tfm = tfm;
	desc.flags = 0;

	sg_init_one(sg, kptr->key, kptr->keylen);
	/*hash the key to the preamble */
	err = crypto_hash_digest(&desc, sg, sg->length, preamble->check_key);

	crypto_free_hash(desc.tfm);

out_no_tfm:
	return err;

}

static int write_preamble(struct file *outfilp,
			const struct cipher_preamble *preamble)
{
	return outfilp->f_op->write(outfilp, (void *)preamble,
				sizeof(*preamble), &outfilp->f_pos);
}

static int validate_preamble(struct file *infilp,
			     struct cipher_preamble *preamble)
{
	struct cipher_preamble check;
	int ret = 0;
	if (infilp->f_op->read(infilp, (void *)&check,
				sizeof(check), &infilp->f_pos)
		!= sizeof(check)) {
	return -EIO;
	}
#ifdef EXTRA_CREDIT
	if (check.cipher_type != preamble->cipher_type)
		ret = -EINVAL;
	preamble->blk_size = check.blk_size;
	memcpy(preamble->iv, check.iv, IV_SIZE);
#endif
	if (memcmp(check.check_key, preamble->check_key, MD5_DIGEST_SIZE) != 0)
		ret = -EINVAL;
	return ret;
}

static int get_cipher_vec(struct cipher_vec *kptr, const struct cipher_vec *ptr)
{
	int err = 0;

	kptr->key = kzalloc(ptr->keylen, GFP_KERNEL);
	if (kptr->key == NULL) {
		err = -ENOMEM;
		goto out;
	}
	err = copy_from_user(kptr->key, ptr->key, ptr->keylen);
	if (err)
		goto out_key;

	kptr->infile = kzalloc(strlen(ptr->infile), GFP_KERNEL);
	if (kptr->infile == NULL) {
		err = -ENOMEM;
		goto out_key;
	}
	err = copy_from_user(kptr->infile, ptr->infile, strlen(ptr->infile));
	if (err)
		goto out_infile;

	kptr->outfile = kzalloc(strlen(ptr->outfile), GFP_KERNEL);
	if (kptr->outfile == NULL) {
		err = -ENOMEM;
		goto out_infile;
	}
	err = copy_from_user(kptr->outfile, ptr->outfile, strlen(ptr->outfile));
	if (err)
		goto out_outfile;

	kptr->flag = ptr->flag;
	kptr->keylen = ptr->keylen;
#ifdef EXTRA_CREDIT
	kptr->cipher_type = ptr->cipher_type;
	kptr->blk_size = ptr->blk_size;
#endif
	goto out;

out_outfile:
	kfree(kptr->outfile);
out_infile:
	kfree(kptr->infile);
out_key:
	kfree(kptr->key);
out:
	return err;
}

static int check_args(struct cipher_vec *kptr)
{
	int err = 0;
	if (kptr->key == NULL || kptr->infile == NULL || kptr->outfile == NULL
	    || (kptr->flag != ENCRYPT && kptr->flag != DECRYPT))
		err = -EINVAL;

#ifdef EXTRA_CREDIT
	if (kptr->cipher_type < 0 ||
		kptr->cipher_type >= sizeof(cipher_opt)/sizeof(char *))
		err = -EINVAL;
	if (check_keylen_blksize(kptr->cipher_type,
				 kptr->keylen, kptr->blk_size) != 0)
		err = -EINVAL;
#endif
	return err;
}

static void set_blksize(struct cipher_preamble *preamble,
			int *in_blksize, int *out_blksize,
			int flag)
{
	if (flag == ENCRYPT) {
#ifdef EXTRA_CREDIT
		*in_blksize = preamble->blk_size;
#else
		*in_blksize = DEFAULT_BLK_SIZE;
#endif
		*out_blksize = *in_blksize + PAD_SIZE;
	} else {
#ifdef EXTRA_CREDIT
		*in_blksize = preamble->blk_size + PAD_SIZE;
#else
		*in_blksize = DEFAULT_BLK_SIZE + PAD_SIZE;
#endif
		*out_blksize = DEFAULT_BLK_SIZE;
	}
}

static int init_cipher(struct blkcipher_desc *desc, struct cipher_vec *kptr,
			struct cipher_preamble *preamble)
{
	int err = 0;

	struct crypto_blkcipher *tfm = NULL;

#ifdef EXTRA_CREDIT
	tfm = crypto_alloc_blkcipher(cipher_opt[kptr->cipher_type],
				     0, CRYPTO_ALG_ASYNC);
#else
	tfm = crypto_alloc_blkcipher("cbc(aes)", 0, CRYPTO_ALG_ASYNC);
#endif

	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		goto out;
	}

	desc->tfm = tfm;
	desc->flags = 0;

	err = crypto_blkcipher_setkey((void *)tfm, kptr->key, kptr->keylen);
	if (err != 0)
		goto out_tfm;

#ifdef EXTRA_CREDIT
	/* use the iv in preamble to set the iv in the cipher */
	memcpy(crypto_blkcipher_crt(desc->tfm)->iv, preamble->iv,
		crypto_blkcipher_ivsize(desc->tfm));
#endif
	goto out;
out_tfm:
	kfree(tfm);
out:
	return err;

}

static int delete_partial_file(struct file *file)
{
	struct dentry *dentry = file->f_dentry;
	struct inode *dir_inode = file->f_dentry->d_parent->d_inode;
	int err = 0;

	filp_close(file, NULL);
	mutex_lock_nested(&(dir_inode->i_mutex), I_MUTEX_PARENT);
	if (dentry)
		if (dir_inode)
			err = vfs_unlink(dir_inode, dentry);

	mutex_unlock(&(dir_inode->i_mutex));
	return err;
}

asmlinkage long xcrypt(void *args)
{
	struct cipher_vec *kptr = NULL;
	int err = 0;
	struct file *infilp = NULL, *outfilp = NULL;
	mm_segment_t oldfs;
	ssize_t bytes = 0;
	void *infilebuf = NULL;
	void *outfilebuf = NULL;
	size_t in_blksize = 0;
	size_t out_blksize = 0;
	struct cipher_preamble *preamble = NULL;
	struct blkcipher_desc *desc = NULL;
	struct cipher_vec *ptr = (struct cipher_vec *)args;

	if (access_ok(VERIFY_READ, ptr, sizeof(struct cipher_vec)) == 0) {
		pr_err("xcrypt: Bad user space address.\n");
		err = -EFAULT;
		goto out;
	}

	kptr = kzalloc(sizeof(*kptr), GFP_KERNEL);
	if (kptr == NULL) {
		err = -ENOMEM;
		goto out;
	}

	err = get_cipher_vec(kptr, args);
	if (err != 0) {
		pr_err("xcrypt: cannot pass arguments.\n");
		goto out_kptr;
	}

	err = check_args(kptr);
	if (err != 0) {
		pr_err("xcrypt: wrong argument(s).\n");
		goto out_kptr;
	}

	preamble = kzalloc(sizeof(*preamble), GFP_KERNEL);
	if (preamble == NULL) {
		err = -ENOMEM;
		goto out_kptr;
	}

	err = set_preamble(kptr, preamble);
	if (err != 0) {
		pr_err("xcrypt: cannot set preamble.\n");
		goto out_preamble;
	}

	infilp = filp_open(kptr->infile, O_RDONLY, 0);
	if (!infilp || IS_ERR(infilp)) {
		pr_err("read file err %d\n", (int) PTR_ERR(infilp));
		err = PTR_ERR(infilp);
		goto out_preamble;
	}

	if (!infilp->f_op->read) {
		err = -EACCES;
		goto out_infile;/* file(system) doesn't allow reads */
	}

	infilp->f_pos = 0;
	oldfs = get_fs();
	set_fs(KERNEL_DS);

	if (kptr->flag == DECRYPT) {
		if (validate_preamble(infilp, preamble) != 0) {
			pr_err("xcrypt: wrong key.\n");
			err = -EKEYREJECTED;
		goto out_infile;
		}
	}
	/**
	* don't truncate here(O_TRUNC), truncate after verifying whether
	* infile and outfile are the same (you don't want to truncate an
	* outfile if it is also an infile).
	*/
	outfilp = filp_open(kptr->outfile, O_CREAT, S_IRUSR|S_IWUSR);
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("write file err %d\n", (int) PTR_ERR(outfilp));
		err = PTR_ERR(outfilp);
		goto out_cipher;
	}
	/* check whether input file and output are the same */
	if ((infilp->f_dentry->d_inode->i_ino
	     == outfilp->f_dentry->d_inode->i_ino) &&
	    (infilp->f_dentry->d_inode->i_sb->s_dev
	     == outfilp->f_dentry->d_inode->i_sb->s_dev)){
		err = -EINVAL;
		pr_err("xcrypt: infile and outfile are the same.\n");
		goto out_outfile;
	}

	/* do truncation here */
	filp_close(outfilp, NULL);
	outfilp = filp_open(kptr->outfile,
			    O_CREAT | O_WRONLY | O_TRUNC,
			    S_IRUSR|S_IWUSR);
	if (!outfilp || IS_ERR(outfilp)) {
		pr_err("write file err %d\n", (int) PTR_ERR(outfilp));
		err = PTR_ERR(outfilp);
		goto out_cipher;
	}

	if (!outfilp->f_op->write) {
		err = -EACCES;
		goto out_outfile;/* file(system) doesn't allow writes */
	}

	outfilp->f_pos = 0;

#ifdef EXTRA_CREDIT
	/* set iv in encryption
	(in decryption, iv has been set in validate_preamble() */
	if (kptr->flag == ENCRYPT)
		set_iv(preamble, outfilp);
#endif
	desc = kzalloc(sizeof(struct blkcipher_desc), GFP_KERNEL);
	if (desc == NULL) {
		err = -ENOMEM;
		goto out_outfile;
	}

	err = init_cipher(desc, kptr, preamble);
	if (err != 0) {
		pr_err("xcrypt: cannot initialize cipher.\n");
		goto out_cipher;
	}

	set_blksize(preamble, &in_blksize, &out_blksize, kptr->flag);

	infilebuf = kzalloc(in_blksize, GFP_KERNEL);
	if (infilebuf == NULL) {
		err = -ENOMEM;
		goto out_cipher;
	}

	outfilebuf = kzalloc(out_blksize, GFP_KERNEL);
	if (outfilebuf == NULL) {
		err = -ENOMEM;
		goto out_infilebuf;
	}

	if (kptr->flag == ENCRYPT) {
		bytes = write_preamble(outfilp, preamble);
		if (bytes != sizeof(*preamble)) {
			err = -EIO;
			goto out_clean_partial_file;
		}
	}

	while ((bytes = infilp->f_op->read(infilp, infilebuf,
					   in_blksize, &infilp->f_pos)) > 0) {

		if (kptr->flag == ENCRYPT)
			err = encrypt(desc, outfilebuf, &out_blksize,
				      infilebuf, bytes);
		else
			err = decrypt(desc, outfilebuf, &out_blksize,
				      infilebuf, bytes);
		if (err != 0) {
			err = -EDOM;/* EDOM indicates en/decryption failed */
			goto out_clean_partial_file;
		}

		bytes = outfilp->f_op->write(outfilp, outfilebuf,
				     out_blksize, &outfilp->f_pos);
		if (bytes != out_blksize) {
			err = -EIO;
			goto out_clean_partial_file;
		}
		memset(infilebuf, 0, sizeof(infilebuf));
	}

	set_fs(oldfs);
	goto out_outfilebuf;

out_clean_partial_file:
	if (delete_partial_file(outfilp))
		pr_err("failed cleaning partial file, need to delete it manually\n");
out_outfilebuf:
	kfree(outfilebuf);
out_infilebuf:
	kfree(infilebuf);
out_cipher:
	kfree(desc->tfm);
	kfree(desc);
out_outfile:
	/* may be closed in delete_partial_file(outfilp) */
	if (outfilp)
		filp_close(outfilp, NULL);
out_infile:
	filp_close(infilp, NULL);
out_preamble:
	kfree(preamble);
out_kptr:
	kfree(kptr->outfile);
	kfree(kptr->infile);
	kfree(kptr->key);
	kfree(kptr);
out:
	return err;
}

int init_module(void)
{
	if (xcryptfxn != NULL)
		return -EPERM;
	xcryptfxn = xcrypt;
	printk(KERN_INFO "load\n");
	return 0;
}

void cleanup_module(void)
{
	if (xcryptfxn == xcrypt)
		xcryptfxn = NULL;
	printk(KERN_INFO "Goodbye\n");
}
