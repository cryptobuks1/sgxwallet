//
// Created by kladko on 06.05.20.
//

#ifndef SGXWALLET_TEST_KEY_GENERATOR
#define SGXWALLET_TEST_KEY_GENERATOR

#define TEST_BLS_KEY_SHARE "4160780231445160889237664391382223604184857153814275770598791864649971919844"
#define TEST_BLS_KEY_NAME "SCHAIN:17:INDEX:5:KEY:1"
#define SAMPLE_HASH "09c6137b97cdf159b9950f1492ee059d1e2b10eaf7d51f3a97d61f2eee2e81db"
#define SAMPLE_HEX_HASH "3F891FDA3704F0368DAB65FA81EBE616F4AA2A0854995DA4DC0B59D2CADBD64F"
#define SAMPLE_KEY_NAME "tmp_NEK:8abc8e8280fb060988b65da4b8cb00779a1e816ec42f8a40ae2daa520e484a01"
#define SAMPLE_AES_KEY "123456789"

#define SAMPLE_POLY_NAME  "POLY:SCHAIN_ID:1:NODE_ID:1:DKG_ID:1"
#define RPC_ENDPOINT  "http://localhost:1029"
#define SAMPLE_PUBLIC_KEY_B "c0152c48bf640449236036075d65898fded1e242c00acb45519ad5f788ea7cbf9a5df1559e7fc87932eee5478b1b9023de19df654395574a690843988c3ff475"


#define SAMPLE_DKG_PUB_KEY_1 "505f55a38f9c064da744f217d1cb993a17705e9839801958cda7c884e08ab4dad7fd8d22953d3ac7f0913de24fd67d7ed36741141b8a3da152d7ba954b0f14e2"
#define SAMPLE_DKG_PUB_KEY_2 "378b3e6fdfe2633256ae1662fcd23466d02ead907b5d4366136341cea5e46f5a7bb67d897d6e35f619810238aa143c416f61c640ed214eb9c67a34c4a31b7d25"


//openssl req -new -newkey rsa:2048 -nodes -keyout yourdomain.key -out yourdomain.csr^
#define SAMPLE_CSR_FILE_NAME "samples/yourdomain.csr"


class TestKeyGenerator {

public:

static string stringFromFr(libff::alt_bn128_Fr &el);

    static vector <libff::alt_bn128_Fr> splitStringToFr(const char *coeffs, const char symbol) ;

    static string convertDecToHex(string dec, int numBytes = 32);

    static vector <string> splitStringTest(const char *coeffs, const char symbol);

    static libff::alt_bn128_G2 vectStringToG2(const vector <string> &G2_str_vect);

    static void sendRPCRequest();

    static void ecdsaTestKeyGen(sgx_enclave_id_t _eid);

    static void blsTestKeyGen();

    static default_random_engine randGen;
};


#endif //SGXWALLET_TESTW_H
