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

    @file TestUtils.cpp
    @author Stan Kladko
    @date 2020
*/

#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include <jsonrpccpp/server/connectors/httpserver.h>
#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/exponentiation/exponentiation.hpp>
#include <libff/algebra/fields/fp.hpp>
#include <dkg/dkg.h>
#include "sgxwallet_common.h"
#include "third_party/intel/create_enclave.h"
#include "secure_enclave_u.h"
#include "third_party/intel/sgx_detect.h"
#include <gmp.h>
#include <sgx_urts.h>
#include <stdio.h>
#include <jsonrpccpp/client/connectors/httpclient.h>
#include <sgx_tcrypto.h>

#include "BLSCrypto.h"
#include "ServerInit.h"
#include "DKGCrypto.h"
#include "SGXException.h"
#include "LevelDB.h"
#include "SGXWalletServer.hpp"

#include "catch.hpp"
#include "BLSSigShare.h"
#include "BLSSigShareSet.h"
#include "BLSPublicKeyShare.h"
#include "BLSPublicKey.h"
#include "SEKManager.h"
#include <thread>
#include "common.h"
#include "stubclient.h"
#include "SGXRegistrationServer.h"
#include "SGXWalletServer.h"
#include "sgxwallet.h"
#include "testw.h"
#include "TestUtils.h"

using namespace jsonrpc;
using namespace std;

default_random_engine TestUtils::randGen((unsigned int) time(0));

string TestUtils::stringFromFr(libff::alt_bn128_Fr &el) {
    mpz_t t;
    mpz_init(t);
    el.as_bigint().to_mpz(t);
    char arr[mpz_sizeinbase(t, 10) + 2];
    char *tmp = mpz_get_str(arr, 10, t);
    mpz_clear(t);

    return string(tmp);
}


string TestUtils::convertDecToHex(string dec, int numBytes) {
    mpz_t num;
    mpz_init(num);
    mpz_set_str(num, dec.c_str(), 10);

    vector<char> tmp(mpz_sizeinbase(num, 16) + 2, 0);
    char *hex = mpz_get_str(tmp.data(), 16, num);

    string result = hex;
    int n_zeroes = numBytes * 2 - result.length();
    result.insert(0, n_zeroes, '0');

    return result;
}

void TestUtils::resetDB() {
    CHECK_STATE(system("bash -c \"rm -rf " SGXDATA_FOLDER "* \"") == 0);
}

shared_ptr <string> TestUtils::encryptTestKey() {
    const char *key = TEST_BLS_KEY_SHARE;
    int errStatus = -1;
    vector<char> errMsg(BUF_LEN, 0);;
    string encryptedKeyHex = encryptBLSKeyShare2Hex(&errStatus, errMsg.data(), key);

    CHECK_STATE(!encryptedKeyHex.empty());
    CHECK_STATE(errStatus == 0);

    return make_shared<string>(encryptedKeyHex);
}

vector <libff::alt_bn128_Fr> TestUtils::splitStringToFr(const char *coeffs, const char symbol) {
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector <libff::alt_bn128_Fr> tokens;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            libff::alt_bn128_Fr coeff(token.c_str());
            tokens.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return tokens;
}

vector <string> TestUtils::splitStringTest(const char *coeffs, const char symbol) {
    string str(coeffs);
    string delim;
    delim.push_back(symbol);
    vector <string> g2Strings;
    size_t prev = 0, pos = 0;
    do {
        pos = str.find(delim, prev);
        if (pos == string::npos) pos = str.length();
        string token = str.substr(prev, pos - prev);
        if (!token.empty()) {
            string coeff(token.c_str());
            g2Strings.push_back(coeff);
        }
        prev = pos + delim.length();
    } while (pos < str.length() && prev < str.length());

    return g2Strings;
}

libff::alt_bn128_G2 TestUtils::vectStringToG2(const vector <string> &G2_str_vect) {
    libff::alt_bn128_G2 coeff = libff::alt_bn128_G2::zero();
    coeff.X.c0 = libff::alt_bn128_Fq(G2_str_vect.at(0).c_str());
    coeff.X.c1 = libff::alt_bn128_Fq(G2_str_vect.at(1).c_str());
    coeff.Y.c0 = libff::alt_bn128_Fq(G2_str_vect.at(2).c_str());
    coeff.Y.c1 = libff::alt_bn128_Fq(G2_str_vect.at(3).c_str());
    coeff.Z.c0 = libff::alt_bn128_Fq::one();
    coeff.Z.c1 = libff::alt_bn128_Fq::zero();

    return coeff;
}

void TestUtils::sendRPCRequest() {
    HttpClient client(RPC_ENDPOINT);
    StubClient c(client, JSONRPC_CLIENT_V2);

    int n = 16, t = 16;
    Json::Value ethKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector <string> pubShares(n);
    vector <string> polyNames(n);

    static atomic<int> counter(1);

    int schainID = counter.fetch_add(1);
    int dkgID = counter.fetch_add(1);
    for (uint8_t i = 0; i < n; i++) {
        ethKeys[i] = c.generateECDSAKey();
        CHECK_STATE(ethKeys[i]["status"] == 0);
        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);
        auto response = c.generateDKGPoly(polyName, t);
        CHECK_STATE(response["status"] == 0);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        CHECK_STATE(verifVects[i]["status"] == 0);

        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["Verification Vector"][k][j].asString();
                pubShares[i] += convertDecToHex(pubShare);
            }
        }
    }

    int k = 0;

    vector <string> secShares(n);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value verif = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n, j);
            CHECK_STATE(verif["status"] == 0);

            k++;
        }

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared < array < uint8_t, 32 >> ();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    map <size_t, shared_ptr<BLSPublicKeyShare>> coeffs_pkeys_map;

    for (int i = 0; i < t; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        string secretShare = secretShares[i]["secretShare"].asString();

        auto response = c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t, n);
        CHECK_STATE(response["status"] == 0);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        CHECK_STATE(pubBLSKeys[i]["status"] == 0);

        string hash = SAMPLE_HASH;
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        CHECK_STATE(blsSigShares[i]["status"] == 0);

        shared_ptr <string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));
    }

    sigShareSet.merge();
}

void TestUtils::destroyEnclave() {
    if (eid != 0) {
        sgx_destroy_enclave(eid);
        eid = 0;
    }
}

void TestUtils::doDKG(StubClient &c, int n, int t,
           vector<string>& _ecdsaKeyNames, vector<string>& _blsKeyNames,
           int schainID, int dkgID) {
    Json::Value ethKeys[n];
    Json::Value verifVects[n];
    Json::Value pubEthKeys;
    Json::Value secretShares[n];
    Json::Value pubBLSKeys[n];
    Json::Value blsSigShares[n];
    vector<string> pubShares(n);
    vector<string> polyNames(n);

    _ecdsaKeyNames.clear();
    _blsKeyNames.clear();

    for (uint8_t i = 0; i < n; i++) {
        ethKeys[i] = c.generateECDSAKey();

        CHECK_STATE(ethKeys[i]["status"] == 0);

        auto keyName = ethKeys[i]["keyName"].asString();
        CHECK_STATE(keyName.size() == ECDSA_KEY_NAME_SIZE);

        _ecdsaKeyNames.push_back(keyName);

        string polyName =
                "POLY:SCHAIN_ID:" + to_string(schainID) + ":NODE_ID:" + to_string(i) + ":DKG_ID:" + to_string(dkgID);

        Json::Value response = c.generateDKGPoly(polyName, t);
        CHECK_STATE(response["status"] == 0);
        polyNames[i] = polyName;
        verifVects[i] = c.getVerificationVector(polyName, t, n);
        CHECK_STATE(verifVects[i]["status"] == 0);
        pubEthKeys.append(ethKeys[i]["publicKey"]);
    }

    for (uint8_t i = 0; i < n; i++) {
        secretShares[i] = c.getSecretShare(polyNames[i], pubEthKeys, t, n);
        CHECK_STATE(secretShares[i]["status"] == 0);
        for (uint8_t k = 0; k < t; k++) {
            for (uint8_t j = 0; j < 4; j++) {
                string pubShare = verifVects[i]["verificationVector"][k][j].asString();
                CHECK_STATE(pubShare.length() > 60);
                pubShares[i] += TestUtils::convertDecToHex(pubShare);
            }
        }
    }

    int k = 0;

    vector<string> secShares(n);

    vector<string> pSharesBad(pubShares);

    for (int i = 0; i < n; i++)
        for (int j = 0; j < n; j++) {
            string secretShare = secretShares[i]["secretShare"].asString().substr(192 * j, 192);
            secShares[i] += secretShares[j]["secretShare"].asString().substr(192 * i, 192);
            Json::Value response = c.dkgVerification(pubShares[i], ethKeys[j]["keyName"].asString(), secretShare, t, n,
                                                     j);
            CHECK_STATE(response["status"] == 0);

            bool res = response["result"].asBool();
            CHECK_STATE(res);

            k++;

            pSharesBad[i][0] = 'q';
            Json::Value wrongVerif = c.dkgVerification(pSharesBad[i], ethKeys[j]["keyName"].asString(), secretShare, t,
                                                       n, j);
            res = wrongVerif["result"].asBool();
            CHECK_STATE(!res);
        }

    BLSSigShareSet sigShareSet(t, n);

    string hash = SAMPLE_HASH;

    auto hash_arr = make_shared<array<uint8_t, 32 >>();
    uint64_t binLen;
    if (!hex2carray(hash.c_str(), &binLen, hash_arr->data())) {
        throw SGXException(INVALID_HEX, "Invalid hash");
    }

    map<size_t, shared_ptr<BLSPublicKeyShare>> pubKeyShares;

    for (int i = 0; i < n; i++) {
        string endName = polyNames[i].substr(4);
        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        _blsKeyNames.push_back(blsName);
        string secretShare = secretShares[i]["secretShare"].asString();

        auto response = c.createBLSPrivateKey(blsName, ethKeys[i]["keyName"].asString(), polyNames[i], secShares[i], t,
                                              n);
        CHECK_STATE(response["status"] == 0);
        pubBLSKeys[i] = c.getBLSPublicKeyShare(blsName);
        CHECK_STATE(pubBLSKeys[i]["status"] == 0);
    }

    for (int i = 0; i < t; i++) {
        vector<string> pubKeyVect;
        for (uint8_t j = 0; j < 4; j++) {
            pubKeyVect.push_back(pubBLSKeys[i]["blsPublicKeyShare"][j].asString());
        }
        BLSPublicKeyShare pubKey(make_shared<vector<string >>(pubKeyVect), t, n);

        pubKeyShares[i + 1] = make_shared<BLSPublicKeyShare>(pubKey);
    }

    // create pub key

    BLSPublicKey blsPublicKey(make_shared<map<size_t, shared_ptr<BLSPublicKeyShare >>>(pubKeyShares), t,
                              n);

    // sign verify a sample sig

    for (int i = 0; i < t; i++) {

        string blsName = "BLS_KEY" + polyNames[i].substr(4);
        blsSigShares[i] = c.blsSignMessageHash(blsName, hash, t, n, i + 1);
        CHECK_STATE(blsSigShares[i]["status"] == 0);
        shared_ptr<string> sig_share_ptr = make_shared<string>(blsSigShares[i]["signatureShare"].asString());
        BLSSigShare sig(sig_share_ptr, i + 1, t, n);
        sigShareSet.addSigShare(make_shared<BLSSigShare>(sig));

        auto pubKey = pubKeyShares[i+1];

        CHECK_STATE(pubKey->VerifySigWithHelper(hash_arr, make_shared<BLSSigShare>(sig), t, n));
    }

    shared_ptr<BLSSignature> commonSig = sigShareSet.merge();

    CHECK_STATE(blsPublicKey.VerifySigWithHelper(hash_arr, commonSig, t, n));

    for (auto&& i : _ecdsaKeyNames)
        cerr << i << endl;

    for (auto&& i : _blsKeyNames)
        cerr << i << endl;
}
