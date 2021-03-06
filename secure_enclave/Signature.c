/*
    Copyright (C) 2019-Present SKALE Labs

    This file is part of sgxwallet.

    sgxwallet is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published
    by the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    sgxwallet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with sgxwallet.  If not, see <https://www.gnu.org/licenses/>.

    @file signature.c
    @author Stan Kladko
    @date 2019
*/

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>
#include <string.h>

#define SAFE_FREE(__X__) if (__X__) {free(__X__); __X__ = NULL;}
#define SAFE_DELETE(__X__) if (__X__) {delete(__X__); __X__ = NULL;}
#define SAFE_CHAR_BUF(__X__, __Y__)  ;char __X__ [ __Y__ ]; memset(__X__, 0, __Y__);


#ifdef USER_SPACE
#include <gmp.h>


#else

#include <../tgmp-build/include/sgx_tgmp.h>

#endif

#include "DomainParameters.h"
#include "Point.h"
#include "NumberTheory.h"
#include "Signature.h"

/*Initialize a signature*/
signature signature_init() {
    signature sig;
    sig = calloc(sizeof(struct signature_s), 1);
    mpz_init(sig->r);
    mpz_init(sig->s);
    sig->v = 0;
    return sig;
}


/*Set signature from strings of a base from 2-62*/
int signature_set_str(signature sig, const char *r, const char *s, int base) {
    if (mpz_set_str(sig->r, r, base) != 0 || mpz_set_str(sig->s, s, base) != 0) {
        return 1;
    }
    return 0;
}

/*Set signature from hexadecimal strings*/
int signature_set_hex(signature sig, const char *r, const char *s) {
    return signature_set_str(sig, r, s, 16);
}

/*Set signature from decimal unsigned long ints*/
void signature_set_ui(signature sig, unsigned long int r, unsigned long int s) {
    mpz_set_ui(sig->r, r);
    mpz_set_ui(sig->s, s);
}

/*Make R a copy of P*/
void signature_copy(signature R, signature sig) {
    mpz_set(R->r, sig->r);
    mpz_set(R->s, sig->s);
}


/*Compare two signatures return 1 if not the same, returns 0 if they are the same*/
bool signature_cmp(signature sig1, signature sig2) {
    return !mpz_cmp(sig1->r, sig2->r) && !mpz_cmp(sig1->s, sig2->s);
}

/*Generates a public key for a private key*/
void signature_extract_public_key(point public_key, mpz_t private_key, domain_parameters curve) {
    point_multiplication(public_key, private_key, curve->G, curve);
}

#ifndef USER_SPACE

/*Generate signature for a message*/
void signature_sign(signature sig, mpz_t message, mpz_t private_key, domain_parameters curve) {
    //message must not have a bit length longer than that of n
    if (mpz_sizeinbase(message, 2) > mpz_sizeinbase(curve->n, 2)) {
        LOG_ERROR("mpz_sizeinbase(message, 2) > mpz_sizeinbase(curve->n, 2))");
        return;
    }

    point Q = point_init();

    //Initializing variables
    mpz_t k, x, r, t1, t2, t3, t4, t5, s, n_div_2, rem, neg, seed;
    mpz_init(k);
    mpz_init(x);
    mpz_init(r);
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(s);
    mpz_init(t4);
    mpz_init(t5);
    mpz_init(n_div_2);
    mpz_init(rem);
    mpz_init(neg);
    mpz_init(seed);
    mpz_t s_mul_2;
    mpz_init(s_mul_2);

    SAFE_CHAR_BUF(rand_char, 32);

    get_global_random(rand_char, 32);

    signature_sign_start:


    get_global_random(rand_char, 32);

    mpz_import(seed, 32, 1, sizeof(rand_char[0]), 0, 0, rand_char);

    mpz_mod(k, seed, curve->p);

    //Calculate x
    point_multiplication(Q, k, curve->G, curve);
    mpz_set(x, Q->x);

    //Calculate r
    mpz_mod(r, x, curve->n);
    if (!mpz_sgn(r))    //Start over if r=0, note haven't been tested memory might die :)
        goto signature_sign_start;


    //Calculate s
    //s = k¯¹(e+d*r) mod n = (k¯¹ mod n) * ((e+d*r) mod n) mod n
    //number_theory_inverse(t1, k, curve->n);//t1 = k¯¹ mod n
    mpz_invert(t1, k, curve->n);
    mpz_mul(t2, private_key, r);    //t2 = d*r
    mpz_add(t3, message, t2);    //t3 = e+t2
    mpz_mod(t4, t3, curve->n);    //t2 = t3 mod n
    mpz_mul(t5, t4, t1);        //t3 = t2 * t1
    mpz_mod(s, t5, curve->n);    //s = t3 mod n

    //Calculate v

    mpz_mod_ui(rem, Q->y, 2);

    mpz_mul_ui(s_mul_2, s, 2);

    unsigned b = 0;
    if (mpz_cmp(s_mul_2, curve->n) > 0) {
        b = 1;
    }
    sig->v = mpz_get_ui(rem) ^ b;

    mpz_cdiv_q_ui(n_div_2, curve->n, 2);

    if (mpz_cmp(s, n_div_2) > 0) {
        mpz_sub(neg, curve->n, s);
        mpz_set(s, neg);
    }

    //Set signature
    mpz_set(sig->r, r);
    mpz_set(sig->s, s);


    point_clear(Q);

    mpz_clear(k);
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(x);
    mpz_clear(rem);
    mpz_clear(neg);
    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);
    mpz_clear(seed);
    mpz_clear(n_div_2);
    mpz_clear(s_mul_2);

}

#endif

/*Release signature*/
void signature_free(signature sig) {
    if (!sig)
        return;
    mpz_clear(sig->r);
    mpz_clear(sig->s);
    free(sig);
}

/*Verify the integrity of a message using it's signature*/
bool signature_verify(mpz_t message, signature sig, point public_key, domain_parameters curve) {

    //Initialize variables
    mpz_t one, w, u1, u2, t, tt2;
    mpz_init(one);
    mpz_init(w);
    mpz_init(u1);
    mpz_init(u2);
    mpz_init(t);
    mpz_init(tt2);

    mpz_set_ui(one, 1);

    point x = point_init();
    point t1 = point_init();
    point t2 = point_init();

    bool result = false;


    if (mpz_cmp(sig->r, one) < 0 &&
        mpz_cmp(curve->n, sig->r) <= 0 &&
        mpz_cmp(sig->s, one) < 0 &&
        mpz_cmp(curve->n, sig->s) <= 0) {
        goto clean;
    }

    //w = s¯¹ mod n
    number_theory_inverse(w, sig->s, curve->n);

    //u1 = message * w mod n
    mpz_mod(tt2, message, curve->n);
    mpz_mul(t, tt2, w);
    mpz_mod(u1, t, curve->n);

    //u2 = r*w mod n
    mpz_mul(t, sig->r, w);
    mpz_mod(u2, t, curve->n);

    //x = u1*G+u2*Q
    point_multiplication(t1, u1, curve->G, curve);
    point_multiplication(t2, u2, public_key, curve);
    point_addition(x, t1, t2, curve);

    //Get the result, by comparing x value with r and verifying that x is NOT at infinity

    result = mpz_cmp(sig->r, x->x) == 0 && !x->infinity;


    clean:


    point_clear(x);
    point_clear(t1);
    point_clear(t2);

    mpz_clear(one);
    mpz_clear(w);
    mpz_clear(u1);
    mpz_clear(u2);
    mpz_clear(t);
    mpz_clear(tt2);

    return result;

}


