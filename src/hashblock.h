// Copyright (c) 2014 The Mini-Blockchain Project

#ifndef HASHBLOCK_H
#define HASHBLOCK_H

#include "uint256.h"

#include "hash/sph_sha2.h"
#include "hash/sph_keccak.h" //sha3
#include "hash/sph_haval.h"
#include "hash/sph_tiger.h"
#include "hash/sph_whirlpool.h"
#include "hash/sph_ripemd.h"

#ifndef QT_NO_DEBUG
#include <string>
#endif

#ifdef GLOBALDEFINED
#define GLOBAL
#else
#define GLOBAL extern
#endif

GLOBAL sph_sha256_context     z_sha256;
GLOBAL sph_sha512_context     z_sha512;
GLOBAL sph_keccak512_context  z_keccak;
GLOBAL sph_whirlpool_context  z_whirlpool;
GLOBAL sph_haval256_5_context z_haval;
GLOBAL sph_tiger_context      z_tiger;
GLOBAL sph_ripemd160_context  z_ripemd;



#define fillz() do { \
    sph_sha512_init(&z_sha512); \
    sph_sha256_init(&z_sha256); \
    sph_keccak512_init(&z_keccak); \
    sph_whirlpool_init(&z_whirlpool); \
    sph_haval256_5_init(&z_haval); \
    sph_tiger_init(&z_tiger); \
    sph_ripemd160_init(&z_ripemd); \
} while (0) 

#define ZSHA256 (memcpy(&ctx_sha256, &z_sha256, sizeof(z_sha256)))
#define ZSHA512 (memcpy(&ctx_sha512, &z_sha512, sizeof(z_sha512)))
#define ZKECCAK (memcpy(&ctx_keccak, &z_keccak, sizeof(z_keccak)))
#define ZWHIRLPOOL (memcpy(&ctx_whirlpool, &z_whirlpool, sizeof(z_whirlpool)))
#define ZHAVAL (memcpy(&ctx_haval, &z_haval, sizeof(z_haval)))
#define ZTIGER (memcpy(&ctx_tiger, &z_tiger, sizeof(z_tiger)))
#define ZRIPEMD (memcpy(&ctx_ripemd, &z_ripemd, sizeof(z_ripemd)))

template<typename T1>
inline uint256 Hash7(const T1 pbegin, const T1 pend)
{
    sph_sha256_context       ctx_sha256;
    sph_sha512_context       ctx_sha512;
    sph_keccak512_context    ctx_keccak;
    sph_whirlpool_context    ctx_whirlpool;
    sph_haval256_5_context   ctx_haval;
    sph_tiger_context        ctx_tiger;
    sph_ripemd160_context    ctx_ripemd;
    static unsigned char pblank[1];

#ifndef QT_NO_DEBUG
    //std::string strhash;
    //strhash = "";
#endif
    
    uint512 hash[7];
    uint256 finalhash;
    for(int i=0; i < 7; i++)
	hash[i] = 0;

    const void* ptr = (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0]));
    size_t sz = (pend - pbegin) * sizeof(pbegin[0]);

    sph_sha256_init(&ctx_sha256);
    // ZSHA256;
    sph_sha256 (&ctx_sha256, ptr, sz);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&hash[0]));
    
    sph_sha512_init(&ctx_sha512);
    // ZSHA512;
    sph_sha512 (&ctx_sha512, ptr, sz);
    sph_sha512_close(&ctx_sha512, static_cast<void*>(&hash[1]));
    
    sph_keccak512_init(&ctx_keccak);
    // ZKECCAK;
    sph_keccak512 (&ctx_keccak, ptr, sz);
    sph_keccak512_close(&ctx_keccak, static_cast<void*>(&hash[2]));

    sph_whirlpool_init(&ctx_whirlpool);
    // ZWHIRLPOOL;
    sph_whirlpool (&ctx_whirlpool, ptr, sz);
    sph_whirlpool_close(&ctx_whirlpool, static_cast<void*>(&hash[3]));
    
    sph_haval256_5_init(&ctx_haval);
    // ZHAVAL;
    sph_haval256_5 (&ctx_haval, ptr, sz);
    sph_haval256_5_close(&ctx_haval, static_cast<void*>(&hash[4]));

    sph_tiger_init(&ctx_tiger);
    // ZTIGER;
    sph_tiger (&ctx_tiger, ptr, sz);
    sph_tiger_close(&ctx_tiger, static_cast<void*>(&hash[5]));

#if 1
    sph_ripemd160_init(&ctx_ripemd);
    // ZRIPEMD;
    sph_ripemd160 (&ctx_ripemd, ptr, sz);
    sph_ripemd160_close(&ctx_ripemd, static_cast<void*>(&hash[6]));

    //printf("%s\n", hash[6].GetHex().c_str());
#endif
    mpz_t bns[7];

    //Take care of zeros and load gmp
    for(int i=0; i < 7; i++){
	if(hash[i]==0)
	    hash[i] = 1;
	mpz_init(bns[i]);
	mpz_set_uint512(bns[i],hash[i]);
    }
 
    mpz_t product;
    mpz_init(product);
    mpz_set_ui(product,1);
    for(int i=0; i < 7; i++){
	mpz_mul(product,product,bns[i]);
    }

    int bytes = mpz_sizeinbase(product, 256);
    char *data = (char*)malloc(bytes);
    mpz_export(data, NULL, -1, 1, 0, 0, product);

    //Free the memory
    for(int i=0; i < 7; i++){
	mpz_clear(bns[i]);
    }
    mpz_clear(product);

    sph_sha256_init(&ctx_sha256);
    // ZSHA256;
    sph_sha256 (&ctx_sha256, data,bytes);
    sph_sha256_close(&ctx_sha256, static_cast<void*>(&finalhash));


    free(data);
    return finalhash;
}






#endif // HASHBLOCK_H

