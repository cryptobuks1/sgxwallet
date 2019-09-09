/*

Copyright 2018 Intel Corporation

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

1. Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

#include "sgxwallet_common.h"
#include "create_enclave.h"
#include "secure_enclave_u.h"
#include "sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>


#include "BLSCrypto.h"
#include "ServerInit.h"

#define ENCLAVE_NAME "secure_enclave.signed.so"


#define CATCH_CONFIG_MAIN  // This tells Catch to provide a main() - only do this in one cpp file

#include "catch.hpp"

void usage() {
    fprintf(stderr, "usage: sgxwallet\n");
    exit(1);
}

sgx_launch_token_t token = {0};
sgx_enclave_id_t eid;
sgx_status_t status;
int updated;

char *encryptKey2Hex(int *errStatus, char *err_string, const char *_key) {
    char *keyArray = (char *) calloc(BUF_LEN, 1);
    uint8_t *encryptedKey = (uint8_t *) calloc(BUF_LEN, 1);
    char *errMsg = (char *) calloc(BUF_LEN, 1);
    strncpy((char *) keyArray, (char *) _key, BUF_LEN);

    *errStatus = -1;

    unsigned int encryptedLen = 0;

    status = encrypt_key(eid, errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

    if (status != SGX_SUCCESS) {
        *errStatus = -1;
        return nullptr;
    }

    if (*errStatus != 0) {
        return nullptr;
    }


    char *result = (char *) calloc(2 * BUF_LEN, 1);

    carray2Hex(encryptedKey, encryptedLen, result);

    return result;
}


char* encryptTestKey() {

    const char *key = "4160780231445160889237664391382223604184857153814275770598"
                      "791864649971919844";


    int errStatus = -1;

    char *errMsg = (char *) calloc(BUF_LEN, 1);

    char *encryptedKeyHex = encryptKey2Hex(&errStatus, errMsg, key);

    REQUIRE(encryptedKeyHex != nullptr);
    REQUIRE(errStatus == 0);

    printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
    printf("Encrypted key len %d\n", (int) strlen(encryptedKeyHex));
    printf("Encrypted key %s \n", encryptedKeyHex);

    return encryptedKeyHex;
}


TEST_CASE("BLS key encrypt", "[bls-key-encrypt]") {


    init_all();
    char* key = encryptTestKey();
    REQUIRE(key != nullptr);

}


TEST_CASE("BLS key encrypt/decrypt", "[bls-key-encrypt-decrypt]") {
    {


        init_all();

        const char *key = "4160780231445160889237664391382223604184857153814275770598"
                          "791864649971919844";

        char *keyArray = (char *) calloc(BUF_LEN, 1);
        uint8_t *encryptedKey = (uint8_t *) calloc(BUF_LEN, 1);
        char *errMsg = (char *) calloc(BUF_LEN, 1);

        strncpy((char *) keyArray, (char *) key, BUF_LEN);

        int errStatus = 0;

        unsigned int encryptedLen = 0;

        status = encrypt_key(eid, &errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

        REQUIRE(status == SGX_SUCCESS);
        REQUIRE(errStatus == 0);

        printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
        printf(" Encrypted key len %d\n", encryptedLen);

        char result[2 * BUF_LEN];

        carray2Hex(encryptedKey, encryptedLen, result);

        uint64_t decodedLen = 0;

        uint8_t decoded[BUF_LEN];

        REQUIRE(hex2carray(result, &decodedLen, decoded));

        for (uint64_t i = 0; i < decodedLen; i++) {
            REQUIRE(decoded[i] == encryptedKey[i]);
        }

        REQUIRE(decodedLen == encryptedLen);

        gmp_printf("Result: %s", result);

        gmp_printf("\n Encrypted length: %d \n", encryptedLen);

        char *plaintextKey = (char *) calloc(BUF_LEN, 1);

        status = decrypt_key(eid, &errStatus, errMsg, decoded, decodedLen, plaintextKey);

        REQUIRE(status == SGX_SUCCESS);
        REQUIRE(errStatus == 0);


        REQUIRE(strcmp(plaintextKey, key) == 0);

        for (int i = 0; i < BUF_LEN; i++) {
            REQUIRE(plaintextKey[i] == keyArray[i]);
        }

        printf("Decrypt key completed with status: %d %s \n", errStatus, errMsg);
        printf("Decrypted key len %d\n", (int) strlen(plaintextKey));
        printf("Decrypted key: %s\n", plaintextKey);


    }
}


TEST_CASE("BLS sign test", "[bls-sign]") {

    init_all();

    const char *key = "4160780231445160889237664391382223604184857153814275770598"
                      "791864649971919844";


    const char *hexHash = "001122334455667788" "001122334455667788" "001122334455667788" "001122334455667788";


    char *keyArray = (char *) calloc(128, 1);

    uint8_t *encryptedKey = (uint8_t *) calloc(1024, 1);

    char *errMsg = (char *) calloc(1024, 1);

    strncpy((char *) keyArray, (char *) key, 128);

    int errStatus = 0;

    unsigned int encryptedLen = 0;

    status = encrypt_key(eid, &errStatus, errMsg, keyArray, encryptedKey, &encryptedLen);

    REQUIRE(status == SGX_SUCCESS);
    REQUIRE(errStatus == 0);


    printf("Encrypt key completed with status: %d %s \n", errStatus, errMsg);
    printf(" Encrypted key len %d\n", encryptedLen);


    char result[2 * BUF_LEN];

    carray2Hex(encryptedKey, encryptedLen, result
    );

    uint64_t dec_len = 0;

    uint8_t bin[BUF_LEN];

    REQUIRE(hex2carray(result, &dec_len, bin)
    );

    for (uint64_t i = 0; i < dec_len; i++) {
        REQUIRE(bin[i] == encryptedKey[i]);
    }

    REQUIRE(dec_len == encryptedLen);

    gmp_printf("Result: %s", result);

    gmp_printf("\n Length: %d \n", encryptedLen);


    char sig[BUF_LEN];

    REQUIRE(sign(result, hexHash, 2, 2, 1, sig));

}


TEST_CASE("DKG gen test", "[dkg-gen]") {

    init_all();

// put your test here
}

