/* 
 * %CopyrightBegin%
 *
 * Copyright Ericsson AB 2010-2011. All Rights Reserved.
 *
 * The contents of this file are subject to the Erlang Public License,
 * Version 1.1, (the "License"); you may not use this file except in
 * compliance with the License. You should have received a copy of the
 * Erlang Public License along with this software. If not, it can be
 * retrieved online at http://www.erlang.org/.
 *
 * Software distributed under the License is distributed on an "AS IS"
 * basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See
 * the License for the specific language governing rights and limitations
 * under the License.
 *
 * %CopyrightEnd%
 */

/*
 * copied from OTP R15B lib/crypto/c_src/crypto.c
 *
 */

#ifdef __WIN32__
    #include <windows.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "erl_nif.h"

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>

#include <openssl/crypto.h>
#include <openssl/sha.h>


#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#ifdef DEBUG
    #  define ASSERT(e) \
    ((void) ((e) ? 1 : (fprintf(stderr,"Assert '%s' failed at %s:%d\n",\
				#e, __FILE__, __LINE__), abort(), 0)))
#else
    #  define ASSERT(e) ((void) 1)
#endif

#ifdef __GNUC__
    #  define INLINE __inline__
#elif defined(__WIN32__)
    #  define INLINE __forceinline
#else
    #  define INLINE
#endif

/* NIF interface declarations */
static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);
static int reload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info);
static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data, ERL_NIF_TERM load_info);
static void unload(ErlNifEnv* env, void* priv_data);

static ERL_NIF_TERM sha256_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha256_init_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha256_update_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
static ERL_NIF_TERM sha256_final_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);


/* openssl callbacks */
#ifdef OPENSSL_THREADS
static void locking_function(int mode, int n, const char *file, int line);
static unsigned long id_function(void);
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file,
							int line);
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr,
			      const char *file, int line);
static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr,
				 const char *file, int line);
#endif /* OPENSSL_THREADS */

static int library_refc = 0; /* number of users of this dynamic library */

static ErlNifFunc nif_funcs[] = {
    {"sha256_nif", 1, sha256_nif},
    {"sha256_init_nif", 0, sha256_init_nif},
    {"sha256_update_nif", 2, sha256_update_nif},
    {"sha256_final_nif", 1, sha256_final_nif},
};

ERL_NIF_INIT(crypto_aux,nif_funcs,load,reload,upgrade,unload)

#define SHA256_LEN	(256/8)

static ErlNifRWLock** lock_vec = NULL; /* Static locks used by openssl */

static int is_ok_load_info(ErlNifEnv* env, ERL_NIF_TERM load_info)
{
    int i;
    return enif_get_int(env,load_info,&i) && i == 0;
}
static void* crypto_alloc(size_t size)
{   
    return enif_alloc(size);
}
static void* crypto_realloc(void* ptr, size_t size)
{
    return enif_realloc(ptr, size);
}   
static void crypto_free(void* ptr)
{   
    enif_free(ptr); 
}

static int load(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{
    ErlNifSysInfo sys_info;
    CRYPTO_set_mem_functions(crypto_alloc, crypto_realloc, crypto_free);

    if (!is_ok_load_info(env, load_info)) {
	return -1;
    }

#ifdef OPENSSL_THREADS
    enif_system_info(&sys_info, sizeof(sys_info));

    if (sys_info.scheduler_threads > 1) {
	int i;
	lock_vec = enif_alloc(CRYPTO_num_locks()*sizeof(*lock_vec));
	if (lock_vec==NULL) return -1;
	memset(lock_vec,0,CRYPTO_num_locks()*sizeof(*lock_vec));

	for (i=CRYPTO_num_locks()-1; i>=0; --i) {
	    lock_vec[i] = enif_rwlock_create("crypto_aux_stat");
	    if (lock_vec[i]==NULL) return -1;
	}
	CRYPTO_set_locking_callback(locking_function);
	CRYPTO_set_id_callback(id_function);
	CRYPTO_set_dynlock_create_callback(dyn_create_function);
	CRYPTO_set_dynlock_lock_callback(dyn_lock_function);
	CRYPTO_set_dynlock_destroy_callback(dyn_destroy_function);
    }
    /* else no need for locks */
#endif /* OPENSSL_THREADS */

    *priv_data = NULL;
    library_refc++;
    return 0;
}

static int reload(ErlNifEnv* env, void** priv_data, ERL_NIF_TERM load_info)
{   
    if (*priv_data != NULL) {
	return -1; /* Don't know how to do that */
    }
    if (library_refc == 0) {
	/* No support for real library upgrade. The tricky thing is to know
	   when to (re)set the callbacks for allocation and locking. */
	return -2;
    }
    if (!is_ok_load_info(env, load_info)) {
	return -1;
    }
    return 0;    
}

static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
		   ERL_NIF_TERM load_info)
{
    int i;
    if (*old_priv_data != NULL) {
	return -1; /* Don't know how to do that */
    }
    i = reload(env,priv_data,load_info);
    if (i != 0) {
	return i;
    }
    library_refc++;
    return 0;
}

static void unload(ErlNifEnv* env, void* priv_data)
{
    if (--library_refc <= 0) {
	CRYPTO_cleanup_all_ex_data();

	if (lock_vec != NULL) {
	    int i;
	    for (i=CRYPTO_num_locks()-1; i>=0; --i) {
		if (lock_vec[i] != NULL) {
		    enif_rwlock_destroy(lock_vec[i]);
		}
	    }
	    enif_free(lock_vec);
	}
    }
    /*else NIF library still used by other (new) module code */
}



static ERL_NIF_TERM sha256_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* (Data) */
    ErlNifBinary ibin;
    ERL_NIF_TERM ret;

    if (!enif_inspect_iolist_as_binary(env, argv[0], &ibin)) {
	return enif_make_badarg(env);
    }
    SHA256((unsigned char *) ibin.data, ibin.size,
	 enif_make_new_binary(env,SHA256_LEN, &ret));
    return ret;
}
static ERL_NIF_TERM sha256_init_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* () */   
    ERL_NIF_TERM ret;
    SHA256_Init((SHA256_CTX *) enif_make_new_binary(env, sizeof(SHA256_CTX), &ret));
    return ret;
}
static ERL_NIF_TERM sha256_update_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* (Context, Data) */
    SHA256_CTX* new_ctx;
    ErlNifBinary ctx_bin, data_bin;
    ERL_NIF_TERM ret;
    if (!enif_inspect_binary(env, argv[0], &ctx_bin) || ctx_bin.size != sizeof(SHA256_CTX)
	|| !enif_inspect_iolist_as_binary(env, argv[1], &data_bin)) {
	return enif_make_badarg(env);
    }
    new_ctx = (SHA256_CTX*) enif_make_new_binary(env,sizeof(SHA256_CTX), &ret);
    memcpy(new_ctx, ctx_bin.data, sizeof(SHA256_CTX));
    SHA256_Update(new_ctx, data_bin.data, data_bin.size);
    return ret;
}
static ERL_NIF_TERM sha256_final_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{/* (Context) */
    ErlNifBinary ctx_bin;
    SHA256_CTX ctx_clone;
    ERL_NIF_TERM ret;
    if (!enif_inspect_binary(env, argv[0], &ctx_bin) || ctx_bin.size != sizeof(SHA256_CTX)) {
	return enif_make_badarg(env);
    }
    memcpy(&ctx_clone, ctx_bin.data, sizeof(SHA256_CTX)); /* writable */
    SHA256_Final(enif_make_new_binary(env, SHA256_LEN, &ret), &ctx_clone);    
    return ret;
}


#ifdef OPENSSL_THREADS /* vvvvvvvvvvvvvvv OPENSSL_THREADS vvvvvvvvvvvvvvvv */

static INLINE void locking(int mode, ErlNifRWLock* lock)
{
    switch (mode) {
    case CRYPTO_LOCK|CRYPTO_READ:
	enif_rwlock_rlock(lock);
	break;
    case CRYPTO_LOCK|CRYPTO_WRITE:
	enif_rwlock_rwlock(lock);
	break;
    case CRYPTO_UNLOCK|CRYPTO_READ:
	enif_rwlock_runlock(lock);
	break;
    case CRYPTO_UNLOCK|CRYPTO_WRITE:
	enif_rwlock_rwunlock(lock);
	break;
    default:
	ASSERT(!"Invalid lock mode");
    }
}

/* Callback from openssl for static locking
 */
static void locking_function(int mode, int n, const char *file, int line)
{
    ASSERT(n>=0 && n<CRYPTO_num_locks());

    locking(mode, lock_vec[n]);
}

/* Callback from openssl for thread id
 */
static unsigned long id_function(void)
{
    return(unsigned long) enif_thread_self();
}

/* Callbacks for dynamic locking, not used by current openssl version (0.9.8)
 */
static struct CRYPTO_dynlock_value* dyn_create_function(const char *file, int line) {
    return(struct CRYPTO_dynlock_value*) enif_rwlock_create("crypto_aux_dyn");
}
static void dyn_lock_function(int mode, struct CRYPTO_dynlock_value* ptr,const char *file, int line)
{
    locking(mode, (ErlNifRWLock*)ptr);
}
static void dyn_destroy_function(struct CRYPTO_dynlock_value *ptr, const char *file, int line)
{
    enif_rwlock_destroy((ErlNifRWLock*)ptr);
}

#endif /* ^^^^^^^^^^^^^^^^^^^^^^ OPENSSL_THREADS ^^^^^^^^^^^^^^^^^^^^^^ */


