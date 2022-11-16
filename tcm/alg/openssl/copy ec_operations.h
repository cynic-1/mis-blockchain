/* ec_operations.h */

#ifndef HEADER_EC_OPERATION_H
#define HEADER_EC_OPERATION_H

#ifdef	__cplusplus
extern "C" {
#endif

#define BN_ULONG	unsigned int

typedef struct bignum_st
	{
	BN_ULONG *d;	/* Pointer to an array of 'BN_BITS2' bit chunks. */
	int top;	/* Index of last used d +1. */
	/* The next are internal book keeping for bn_expand. */
	int dmax;	/* Size of the d array. */
	int neg;	/* one if the number is negative */
	int flags;
	} BIGNUM;

typedef struct ec_point_st {
	BIGNUM X;
	BIGNUM Y;
	BIGNUM Z; /* Jacobian projective coordinates:
	           * (X, Y, Z)  represents  (X/Z^2, Y/Z^3)  if  Z != 0 */
	int Z_is_one; /* enable optimized point arithmetics for special case */

} EC_POINT /* EC_POINT */;

typedef struct ec_group_st {
	BIGNUM p; /* Field specification.
	               * For curves over GF(p), this is the modulus. */

	BIGNUM a, b; /* Curve coefficients.
	              * (Here the assumption is that BIGNUMs can be used
	              * or abused for all kinds of fields, not just GF(p).)
	              * For characteristic  > 3,  the curve is defined
	              * by a Weierstrass equation of the form
	              *     y^2 = x^3 + a*x + b.
	              */
	int a_is_minus3; /* enable optimized point arithmetics for special case */

	EC_POINT *generator; /* optional */
	BIGNUM order, cofactor;
}EC_GROUP /* EC_GROUP */;


//#define TEST
//#define TEST_FIXED


/* ��Բ����Ⱥgroup�ͻ���G��ȫ�ֱ��� */
EC_GROUP *group;
EC_POINT *G;

/* ��Կ���� */
extern unsigned int g_uNumbits;
/* ��ǰʹ�õ�HASH����,������ǩ��ǰ�Ĵ��� */
extern unsigned int g_uSCH_Numbits;

#define NUMBITS		256

/* sch�Ӵճ��� */
//#define SCH_NUMBITS		NUMBITS
//#define SCH_NUMBITS_256	256

/* Hash��kdf��ʹ��256bit�� */
#define HASH_NUMBITS	256
#define KDF_NUMBITS		HASH_NUMBITS

#define	RANDOM_LEN	((1+g_uNumbits/128)*16)

EC_POINT *EC_POINT_new();
void EC_POINT_free(EC_POINT *point);
int EC_POINT_is_at_infinity(const EC_GROUP *group,const EC_POINT *point);
int EC_POINT_set_to_infinity(const EC_GROUP *group,EC_POINT *point);
int EC_POINT_copy(EC_POINT *dest, const EC_POINT *src);
void EC_POINT_print(EC_POINT *P);
int EC_POINT_set_point(EC_POINT *point,const BIGNUM *x,const BIGNUM *y,const BIGNUM *z);
int EC_POINT_get_point(const EC_POINT *point,BIGNUM *x,BIGNUM *y,BIGNUM *z);
int EC_POINT_invert(const EC_GROUP *group,EC_POINT *point);
int EC_POINT_affine2gem(const EC_GROUP *group,const EC_POINT *P,EC_POINT *R);

/* ��������ļӷ� */
int EC_POINT_add(const EC_GROUP *group, EC_POINT *R, const EC_POINT *P0,const EC_POINT *P1);
int EC_POINT_sub(const EC_GROUP *group, EC_POINT *R, const EC_POINT *P0, const EC_POINT *P1);
int EC_POINT_mul(const EC_GROUP *group,EC_POINT *S,const BIGNUM *n, const EC_POINT *P);
int EC_POINT_dbl(const EC_GROUP *group, EC_POINT *R, const EC_POINT *P);

EC_GROUP *EC_GROUP_new();
void EC_GROUP_free(EC_GROUP *group);
int EC_GROUP_set_curve_GFp(EC_GROUP *group, const BIGNUM *p, const BIGNUM *a, const BIGNUM *b);
int EC_GROUP_get_curve_GFp(const EC_GROUP *group, BIGNUM *p, BIGNUM *a, BIGNUM *b);
int EC_GROUP_set_generator(EC_GROUP *group, const EC_POINT *generator, const BIGNUM *order, const BIGNUM *cofactor);
int EC_GROUP_set_order(EC_GROUP *group,const  BIGNUM *order);
int EC_GROUP_get_order(const EC_GROUP *group, BIGNUM *r);
int EC_GROUP_get_cofactor(const EC_GROUP *group, BIGNUM *cofactor);
/* �жϵ��Ƿ��������� */
int EC_POINT_is_on_curve(const EC_GROUP *group, const EC_POINT *point);

/******************************************WAPI*******************************************/

int ECC_Signature(unsigned char *pSignature, const EC_GROUP *group, const EC_POINT *G, const BIGNUM *ka, unsigned char *pDigest);
int ECC_Verify(const EC_GROUP *group, const EC_POINT *G, const EC_POINT *Pa, unsigned char *pDigest, unsigned char *pSignature);
int ECC_Encrypt(unsigned char *cipher,const EC_GROUP *group,const EC_POINT *G,const EC_POINT *Pb,unsigned char *msg,const int msgLen);
int ECC_Decrypt(unsigned char *msg,const EC_GROUP *group,unsigned char *cipher,unsigned int cipherLen,const BIGNUM *kb);


/* �õ����ߵ�bitλ�� */
int tcm_ecc_get_numberbit(unsigned int *puNum);


/* ��Բ���߳�ʼ������ */
int tcm_ecc_init();
int tcm_ecc_release();

int tcm_ecc_init_test256();
int tcm_ecc_init_test192();

/* ����EC��Բ���ߵ��жϱ��ش��Ƿ��ʾ�����ϵ�һ���㣬����ǣ�ת��Ϊ��ѹ����ʽ��������0 */
int tcm_ecc_string_to_uncompressed(unsigned char *pPubkey_in, unsigned int pubkeyLen_in,
								unsigned char *string, unsigned int *puStringLen);

/* ��Բ������Կ�����ɺ��� */
int tcm_ecc_genkey(unsigned char *pPrikey_out, unsigned int *pPrikeyLen_out, unsigned char *pPubkey_out, unsigned int *pPubkeyLen_out);



/* ��Բ���߼��ܺ��� */
int tcm_ecc_encrypt(unsigned char *pPlaintext_in, unsigned int plaintextLen_in, unsigned char *pPubkey_in, unsigned int pubkeyLen_in, unsigned char *pCipher_out, unsigned int *pCipherLen_out);

/* ��Բ���߽��ܺ��� */
int tcm_ecc_decrypt(unsigned char *pCipher_in, unsigned int cipherLen_in, 
					unsigned char *pPrikey_in, unsigned int prikeyLen_in, 
					unsigned char *pPlaintext_out, unsigned int *pPlaintextLen_out);

/* ��Բ����ǩ������ */
int tcm_ecc_signature(	   unsigned char *pDigest, unsigned int uDigestLen,
						   unsigned char *pPrikey_in, unsigned int prikeyLen_in, 
						   unsigned char *pSigData,
						   unsigned int *puSigDataLen);
/* ��Բ������֤���� */
int tcm_ecc_verify(unsigned char *pDigest, unsigned int uDigestLen, unsigned char *pSigndata_in, unsigned int signdataLen_in, unsigned char *pPubkey_in, unsigned int pubkeyLen_in);

/* pKeySeed = pPriKey*pPubKey */
int tcm_ecc_keyseed(unsigned char *pPrikey_in, unsigned int prikeyLen_in, unsigned char *pPubkey_in, unsigned int pubkeyLen_in, unsigned char *pKeySeed_out, unsigned int *pKeySeedLen_out);

/*�������������*/
int tcm_rng( unsigned int rng_len, unsigned char *prngdata_out);
int tcm_BN_pseudo_rand(BIGNUM *rnd, int bits);

/*��ϣ����*/
int tcm_sch_hash( unsigned int datalen_in, unsigned char *pdata_in, unsigned char *pdata_out);
int tcm_sch_192( unsigned int datalen_in, unsigned char *pdata_in, unsigned char *pdata_out);
int tcm_sch_256( unsigned int datalen_in, unsigned char *pdata_in, unsigned char *pdata_out);


/*��Կ��������*/
int tcm_kdf(/*out*/unsigned char *mask, /*in*/int klen, /*in*/unsigned char *z, /*in*/ int zlen);

/*������Ϣ��hashֵ*/
int tcm_calculate_hash(unsigned char *msg, unsigned int msgLen,  
					   unsigned char  *userID, unsigned short int userIDLen, 
					   unsigned char *pPubkey_in, unsigned int pubkeyLen_in,
					   unsigned char *pDigest,
					   unsigned int *puDigestLen);
	


/******************************************WAPI*******************************************/

#ifdef	__cplusplus
}
#endif

#endif
