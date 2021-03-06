/**
 * This file is generated by jsonrpcstub, DO NOT CHANGE IT MANUALLY!
 */

#ifndef JSONRPC_CPP_STUB_STUBCLIENT_H_
#define JSONRPC_CPP_STUB_STUBCLIENT_H_

#include <jsonrpccpp/client.h>

class StubClient : public jsonrpc::Client
{
    public:
        StubClient(jsonrpc::IClientConnector &conn, jsonrpc::clientVersion_t type = jsonrpc::JSONRPC_CLIENT_V2) : jsonrpc::Client(conn, type) {}

        Json::Value importBLSKeyShare(const std::string& keyShare, const std::string& keyShareName, int t, int n, int index)
        {
            Json::Value p;
            p["index"] = index;
            p["keyShare"] = keyShare;
            p["keyShareName"] = keyShareName;
            p["n"] = n;
            p["t"] = t;
            Json::Value result = this->CallMethod("importBLSKeyShare",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value blsSignMessageHash(const std::string& keyShareName, const std::string& messageHash, int t, int n, int signerIndex) 
        {
            Json::Value p;
            p["keyShareName"] = keyShareName;
            p["messageHash"] = messageHash;
            p["n"] = n;
            p["signerIndex"] = signerIndex;
            p["t"] = t;
            Json::Value result = this->CallMethod("blsSignMessageHash",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value importECDSAKey(const std::string& key, const std::string& keyName) 
        {
            Json::Value p;
            p["key"] = key;
            p["keyName"] = keyName;
            Json::Value result = this->CallMethod("importECDSAKey",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value generateECDSAKey() 
        {
          Json::Value p;
          p = Json::nullValue;
          Json::Value result = this->CallMethod("generateECDSAKey",p);
          if (result.isObject())
            return result;
          else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value renameECDSAKey(const std::string& KeyName, const std::string& tempKeyName) 
        {
          Json::Value p;
          p["keyName"] = KeyName;
          p["tempKeyName"] = tempKeyName;
          Json::Value result = this->CallMethod("renameECDSAKey",p);
          if (result.isObject())
            return result;
          else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value getPublicECDSAKey(const std::string& keyName) 
        {
            Json::Value p;
            p["keyName"] = keyName;
            Json::Value result = this->CallMethod("getPublicECDSAKey",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value ecdsaSignMessageHash(int base, const std::string& keyName, const std::string& messageHash) 
        {
            Json::Value p;
            p["base"] = base;
            p["keyName"] = keyName;
            p["messageHash"] = messageHash;
            Json::Value result = this->CallMethod("ecdsaSignMessageHash",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value generateDKGPoly(const std::string& polyName, int t) 
        {
            Json::Value p;
            p["polyName"] = polyName;
            p["t"] = t;
            Json::Value result = this->CallMethod("generateDKGPoly",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value getVerificationVector(const std::string& polyName, int t, int n) 
        {
            Json::Value p;
            p["polyName"] = polyName;
            p["n"] = n;
            p["t"] = t;
            Json::Value result = this->CallMethod("getVerificationVector",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value getSecretShare(const std::string& polyName, const Json::Value& publicKeys, int t, int n) 
        {
            Json::Value p;
            p["polyName"] = polyName;
            p["publicKeys"] = publicKeys;
            p["n"] = n;
            p["t"] = t;
            Json::Value result = this->CallMethod("getSecretShare",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value dkgVerification(const std::string& publicShares, const std::string& ethKeyName, const std::string& SecretShare, int t, int n, int index) 
        {
            Json::Value p;
            p["ethKeyName"] = ethKeyName;
            p["secretShare"] = SecretShare;
            p["index"] = index;
            p["n"] = n;
            p["publicShares"] = publicShares;
            p["t"] = t;
            Json::Value result = this->CallMethod("dkgVerification",p);
            if (result.isObject())
              return result;
            else
              throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value createBLSPrivateKey(const std::string & blsKeyName, const std::string& ethKeyName, const std::string& polyName, const std::string& SecretShare, int t, int n) 
        {
          Json::Value p;
          p["blsKeyName"] = blsKeyName;
          p["ethKeyName"] = ethKeyName;
          p["polyName"] = polyName;
          p["secretShare"] = SecretShare;
          p["n"] = n;
          p["t"] = t;
          Json::Value result = this->CallMethod("createBLSPrivateKey",p);
          if (result.isObject())
           return result;
          else
           throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value getBLSPublicKeyShare(const std::string & blsKeyName) 
        {
            Json::Value p;
            p["blsKeyName"] = blsKeyName;

            Json::Value result = this->CallMethod("getBLSPublicKeyShare",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value complaintResponse(const std::string& polyName, int ind) 
        {
          Json::Value p;
          p["polyName"] = polyName;
          p["ind"] = ind;
          Json::Value result = this->CallMethod("complaintResponse",p);
          if (result.isObject())
            return result;
          else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value multG2(const std::string & x) 
        {
            Json::Value p;
            p["x"] = x;

            Json::Value result = this->CallMethod("multG2",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value isPolyExists(const std::string & polyName) 
        {
            Json::Value p;
            p["polyName"] = polyName;

            Json::Value result = this->CallMethod("isPolyExists",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }

        Json::Value deleteBlsKey(const std::string & polyName)
        {
            Json::Value p;
            p["blsKeyName"] = polyName;

            Json::Value result = this->CallMethod("deleteBlsKey",p);
            if (result.isObject())
                return result;
            else
                throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
        }


    ////CSRManagerServer

  Json::Value getUnsignedCSRs() 
  {
    Json::Value p;
    p = Json::nullValue;
    Json::Value result = this->CallMethod("getUnsignedCSRs",p);
    if (result.isObject())
      return result;
    else
      throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
  }



    Json::Value signByHash(const std::string& hash, int status) 
    {
        Json::Value p;
        p["hash"] = hash;
        p["status"] = status;
        Json::Value result = this->CallMethod("signByHash",p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }


    Json::Value getServerStatus()
    {
        Json::Value p;
        p = Json::nullValue;
        Json::Value result = this->CallMethod("getServerStatus",p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }

    Json::Value getServerVersion() {
        Json::Value p;
        p = Json::nullValue;
        Json::Value result = this->CallMethod("getServerVersion",p);
        if (result.isObject())
            return result;
        else
            throw jsonrpc::JsonRpcException(jsonrpc::Errors::ERROR_CLIENT_INVALID_RESPONSE, result.toStyledString());
    }

};

#endif //JSONRPC_CPP_STUB_STUBCLIENT_H_
