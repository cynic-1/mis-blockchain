/* lhash.h */

#ifndef HEADER_LHASH_H
#define HEADER_LHASH_H

#ifndef OPENSSL_NO_FP_API
#include <stdio.h>
#endif

#ifdef  __cplusplus
extern "C" {
#endif

typedef struct lhash_node_st
	{
	const void *data;
	struct lhash_node_st *next;
#ifndef OPENSSL_NO_HASH_COMP
	unsigned int hash;
#endif
	} LHASH_NODE;

typedef int (*LHASH_COMP_FN_TYPE)(const void *, const void *);
typedef unsigned int (*LHASH_HASH_FN_TYPE)(const void *);
typedef void (*LHASH_DOALL_FN_TYPE)(const void *);
typedef void (*LHASH_DOALL_ARG_FN_TYPE)(const void *, void *);

/* Fourth: "doall_arg" functions */
#define DECLARE_LHASH_DOALL_ARG_FN(f_name,o_type,a_type) \
	void f_name##_LHASH_DOALL_ARG(const void *, void *);
#define IMPLEMENT_LHASH_DOALL_ARG_FN(f_name,o_type,a_type) \
	void f_name##_LHASH_DOALL_ARG(const void *arg1, void *arg2) { \
		o_type a = (o_type)arg1; \
		a_type b = (a_type)arg2; \
		f_name(a,b); }
#define LHASH_DOALL_ARG_FN(f_name) f_name##_LHASH_DOALL_ARG

typedef struct lhash_st
	{
	LHASH_NODE **b;
	LHASH_COMP_FN_TYPE comp;
	LHASH_HASH_FN_TYPE hash;
	unsigned int num_nodes;
	unsigned int num_alloc_nodes;
	unsigned int p;
	unsigned int pmax;
	unsigned int up_load; /* load times 256 */
	unsigned int down_load; /* load times 256 */
	unsigned int num_items;

	unsigned int num_expands;
	unsigned int num_expand_reallocs;
	unsigned int num_contracts;
	unsigned int num_contract_reallocs;
	unsigned int num_hash_calls;
	unsigned int num_comp_calls;
	unsigned int num_insert;
	unsigned int num_replace;
	unsigned int num_delete;
	unsigned int num_no_delete;
	unsigned int num_retrieve;
	unsigned int num_retrieve_miss;
	unsigned int num_hash_comps;

	int error;
	} LHASH;

#define LH_LOAD_MULT	256

#define lh_error(lh)	((lh)->error)

LHASH *lh_new(LHASH_HASH_FN_TYPE h, LHASH_COMP_FN_TYPE c);
void lh_free(LHASH *lh);
void *lh_insert(LHASH *lh, const void *data);
void *lh_delete(LHASH *lh, const void *data);
void *lh_retrieve(LHASH *lh, const void *data);
void lh_doall(LHASH *lh, LHASH_DOALL_FN_TYPE func);
void lh_doall_arg(LHASH *lh, LHASH_DOALL_ARG_FN_TYPE func, void *arg);
unsigned int lh_strhash(const char *c);
unsigned int lh_num_items(const LHASH *lh);

#ifdef  __cplusplus
}
#endif

#endif

