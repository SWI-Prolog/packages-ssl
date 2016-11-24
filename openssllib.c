#include <openssl/crypto.h>

 /* Don't use this structure directly. */
 typedef struct crypto_threadid_st
         {
         void *ptr;
         unsigned long val;
         } CRYPTO_THREADID;
 /* Only use CRYPTO_THREADID_set_[numeric|pointer]() within callbacks */
 void CRYPTO_THREADID_set_numeric(CRYPTO_THREADID *id, unsigned long val);
 void CRYPTO_THREADID_set_pointer(CRYPTO_THREADID *id, void *ptr);
 int CRYPTO_THREADID_set_callback(void (*threadid_func)(CRYPTO_THREADID *));
 void (*CRYPTO_THREADID_get_callback(void))(CRYPTO_THREADID *);
 void CRYPTO_THREADID_current(CRYPTO_THREADID *id);
 int CRYPTO_THREADID_cmp(const CRYPTO_THREADID *a,
                         const CRYPTO_THREADID *b);
 void CRYPTO_THREADID_cpy(CRYPTO_THREADID *dest,
                          const CRYPTO_THREADID *src);
 unsigned long CRYPTO_THREADID_hash(const CRYPTO_THREADID *id);

 int CRYPTO_num_locks(void);

 /* struct CRYPTO_dynlock_value needs to be defined by the user */
 struct CRYPTO_dynlock_value;

 void CRYPTO_set_dynlock_create_callback(struct CRYPTO_dynlock_value *
        (*dyn_create_function)(const char *file, int line));
 void CRYPTO_set_dynlock_lock_callback(void (*dyn_lock_function)
        (int mode, struct CRYPTO_dynlock_value *l,
        const char *file, int line));
 void CRYPTO_set_dynlock_destroy_callback(void (*dyn_destroy_function)
        (struct CRYPTO_dynlock_value *l, const char *file, int line));

 int CRYPTO_get_new_dynlockid(void);

 void CRYPTO_destroy_dynlockid(int i);

 void CRYPTO_lock(int mode, int n, const char *file, int line);

 #define CRYPTO_w_lock(type)    \
        CRYPTO_lock(CRYPTO_LOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
 #define CRYPTO_w_unlock(type)  \
        CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_WRITE,type,__FILE__,__LINE__)
 #define CRYPTO_r_lock(type)    \
        CRYPTO_lock(CRYPTO_LOCK|CRYPTO_READ,type,__FILE__,__LINE__)
 #define CRYPTO_r_unlock(type)  \
        CRYPTO_lock(CRYPTO_UNLOCK|CRYPTO_READ,type,__FILE__,__LINE__)
 #define CRYPTO_add(addr,amount,type)   \
        CRYPTO_add_lock(addr,amount,type,__FILE__,__LINE__)
