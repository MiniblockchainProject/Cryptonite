// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "base58.h"
#include "core.h"
#include "init.h"
#include "keystore.h"
#include "main.h"
#include "net.h"
#include "rpcserver.h"
#include "rpcclient.h"
#include "uint256.h"
#include "script.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
#endif

#include <stdint.h>

#include <boost/assign/list_of.hpp>
#include "json/json_spirit_utils.h"
#include "json/json_spirit_value.h"

using namespace std;
using namespace boost;
using namespace boost::assign;
using namespace json_spirit;

void ComposeSig(CTxIn &txin, vector<pair<uint160, vector<unsigned char> > > &recoveredKeys, vector<uint160> &explicitKeys){
    txin.scriptSig.clear();
    txin.scriptSig.push_back(recoveredKeys.size());

    for(unsigned i=0; i < recoveredKeys.size(); i++){
	txin.scriptSig.insert(txin.scriptSig.end(),recoveredKeys[i].second.begin(),recoveredKeys[i].second.end());
    }

    for(unsigned i=0; i < explicitKeys.size(); i++){
	txin.scriptSig.insert(txin.scriptSig.end(),(uint8_t*)&explicitKeys[i], ((uint8_t*)(&explicitKeys[i]))+20);
    }
}


bool DecomposeSig(uint256 hash, vector<unsigned char> sig, vector<pair<uint160, vector<unsigned char> > > &recoveredKeys, vector<uint160> &explicitKeys){
    uint32_t nSigs = sig[0];
    uint32_t nHashStart = nSigs*65 + 1;
    uint32_t nHashArea = sig.size() - nHashStart;
    uint32_t nHashSigs = nHashArea/20;

    CPubKey key;
    for(uint32_t i=0; i < nSigs; i++){
        if(!key.RecoverCompact(hash,&sig[1+i*65])){
	    return false;
	}

	vector<unsigned char> sigpart;
	sigpart.assign(&sig[1+i*65], &sig[1+i*65] + 65);

	CBitcoinAddress address(key.GetID());
	recoveredKeys.push_back(pair<uint160, vector<unsigned char> >(key.GetID(),sigpart));
    }	

    for(uint32_t i=0; i < nHashSigs; i++){
	uint160 temp;
	memcpy(&temp, &sig[nHashStart + i * 20], 20);
	explicitKeys.push_back(temp);
    }

    return true;
}

bool GetKeysFromSig(uint256 hash, vector<unsigned char> sig, vector<uint160> &recoveredKeys, vector<uint160> &explicitKeys){
    vector<pair<uint160, vector<unsigned char> > > recoveredPairs;
    if(!DecomposeSig(hash,sig,recoveredPairs,explicitKeys))
	return false;

    for(uint32_t i=0; i < recoveredPairs.size(); i++){
	recoveredKeys.push_back(recoveredPairs[i].first);
    }

    return true;
}

bool SignOnce(CTransaction &tx, uint256 hash, unsigned idx, CKey key){
    vector<pair<uint160, vector<unsigned char> > > recoveredPairs;
    vector<uint160> explicitKeys;
    if(!DecomposeSig(hash,tx.vin[idx].scriptSig,recoveredPairs,explicitKeys))
	return false;

    uint160 id = key.GetPubKey().GetID();
    for(unsigned i=0; i < explicitKeys.size(); i++){
	if(explicitKeys[i] != id)
	    continue;

	vector<unsigned char> vchSig;
        if (!key.SignCompact(hash, vchSig))
            return false;

        recoveredPairs.push_back(pair<uint160, vector<unsigned char> >(id,vchSig));
	explicitKeys.erase(explicitKeys.begin() + i);

	sort(recoveredPairs.begin(),recoveredPairs.end());

	ComposeSig(tx.vin[idx],recoveredPairs,explicitKeys);
	return true;
    }

    return false;
}

uint160 ValueFromSig(uint256 hash, vector<unsigned char> sig, Object &o, int assumedSigs){
    uint32_t nSigs = sig[0];
    o.push_back(Pair("nSigs",sig[0]));

    uint32_t nHashStart = nSigs*65 + 1;

    if(sig.size() < nHashStart){
	o.push_back(Pair("valid", false));
	return 0;
    }

    uint32_t nHashArea = sig.size() - nHashStart;
    if(nHashArea%20){
	o.push_back(Pair("valid", false));
	return 0;
    }

    uint32_t nHashSigs = nHashArea/20;

    o.push_back(Pair("nHashSigs",(boost::uint64_t)nHashSigs));

    Object signs;
    vector<uint160> recoveredKeys;
    vector<uint160> explicitKeys;

    if(!GetKeysFromSig(hash,sig,recoveredKeys,explicitKeys)){
	o.push_back(Pair("valid", false));
	return 0;
    }

    for(uint32_t i=0; i < nSigs; i++){
	signs.push_back(Pair("address",CBitcoinAddress(CKeyID(recoveredKeys[i])).ToString()));
    }

    o.push_back(Pair("signed_by",signs));

    Object hashes;
    for(uint32_t i=0; i < nHashSigs; i++){
	hashes.push_back(Pair("address",CBitcoinAddress(CKeyID(explicitKeys[i])).ToString()));
    }

    o.push_back(Pair("hashed_by",hashes));

    if(!is_sorted(recoveredKeys.begin(),recoveredKeys.end())
	    || !is_sorted(explicitKeys.begin(),explicitKeys.end())){
	o.push_back(Pair("valid", false));
	return 0;
    }

    //combine the vectors
    vector<uint160> allKeys;
    allKeys.insert(allKeys.end(), recoveredKeys.begin(), recoveredKeys.end());
    allKeys.insert(allKeys.end(), explicitKeys.begin(), explicitKeys.end());

    sort(allKeys.begin(),allKeys.end());

    if(allKeys.size()==1){
	o.push_back(Pair("valid", true));
	o.push_back(Pair("recovered_adr", CBitcoinAddress(CKeyID(allKeys[0])).ToString()));
	return allKeys[0];
    }

    char data[allKeys.size()*20 + 1];
    for(uint32_t i=0; i < allKeys.size(); i++){
	memcpy(&data[i*20],&allKeys[i],20);
    }
    data[sizeof(data)-1] = nSigs;
    uint160 recHash = Hash160(data,data+sizeof(data));	

    o.push_back(Pair("valid", true));
    o.push_back(Pair("recovered_adr", CBitcoinAddress(CKeyID(recHash)).ToString()));

    if(assumedSigs){
    	data[sizeof(data)-1] = assumedSigs;
    	uint160 assHash = Hash160(data,data+sizeof(data));	
        o.push_back(Pair("if_signed_adr", CBitcoinAddress(CKeyID(assHash)).ToString()));
    }

    return recHash;
}

void TxToJSON(const CTransaction& tx, const uint256 hashBlock, Object& entry, map<int,int> *mapSigs=0)
{
    entry.push_back(Pair("txid", tx.GetTxID().GetHex()));
    entry.push_back(Pair("version", tx.nVersion));
    entry.push_back(Pair("lockheight", (boost::uint64_t)tx.nLockHeight));
    entry.push_back(Pair("msg",string(tx.msg.begin(),tx.msg.end())));
    Array vin;
    for(unsigned i=0; i < tx.vin.size(); i++)
    {
	const CTxIn &txin = tx.vin[i];
        Object in;
	bool coinBase = tx.IsCoinBase();
        in.push_back(Pair("coinbase", coinBase));
        //sa ToDo: Fix. Currently pubKey is the pubKeyHash in hex which is a bit redundant. We already show the pubKeyHash in base58.
        in.push_back(Pair("pubKey", txin.pubKey.GetHex()));
	in.push_back(Pair("address", CBitcoinAddress(CKeyID(txin.pubKey)).ToString()));

        if (!coinBase)
        {
            Object o;
            o.push_back(Pair("hex", HexStr(txin.scriptSig.begin(), txin.scriptSig.end())));
	    if(txin.scriptSig.size()){
		Object sigAsm;
		int assumedSigs=0;
		if(mapSigs && mapSigs->find(i) != mapSigs->end())
		    assumedSigs = (*mapSigs)[i];
		uint160 recoveredHash = ValueFromSig(SignatureHash(tx),txin.scriptSig,sigAsm,assumedSigs);
		o.push_back(Pair("asm",sigAsm));
		o.push_back(Pair("signed", recoveredHash==txin.pubKey));
	    }else{
		o.push_back(Pair("signed",false));
            }		
            in.push_back(Pair("scriptSig", o));
        }
        in.push_back(Pair("value", ValueFromAmount(txin.nValue)));
        vin.push_back(in);
    }
    entry.push_back(Pair("vin", vin));
    Array vout;
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& txout = tx.vout[i];
        Object out;
        out.push_back(Pair("value", ValueFromAmount(txout.nValue)));
        out.push_back(Pair("n", (boost::int64_t)i));
        out.push_back(Pair("pubKey", txout.pubKey.GetHex()));
	out.push_back(Pair("address", CBitcoinAddress(CKeyID(txout.pubKey)).ToString()));
        vout.push_back(out);
    }
    entry.push_back(Pair("vout", vout));

    if(tx.fSetLimit){
	entry.push_back(Pair("limit", ValueFromAmount(tx.nLimitValue)));
    }

    if (hashBlock != 0)
    {
        entry.push_back(Pair("blockhash", hashBlock.GetHex()));
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
        if (mi != mapBlockIndex.end() && (*mi).second)
        {
            CBlockIndex* pindex = (*mi).second;
            if (chainActive.Contains(pindex))
            {
                entry.push_back(Pair("confirmations", 1 + chainActive.Height() - pindex->nHeight));
                entry.push_back(Pair("time", (boost::int64_t)pindex->nTime));
                entry.push_back(Pair("blocktime", (boost::int64_t)pindex->nTime));
            }
            else
                entry.push_back(Pair("confirmations", 0));
        }
    }
}

Value getrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "getrawtransaction \"txid\" ( verbose )\n"	
            "\nReturn the raw transaction data.\n"
            "\nIf verbose=0, returns a string that is serialized, hex-encoded data for 'txid'.\n"
            "If verbose is non-zero, returns an Object with information about 'txid'.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction id\n"
            "2. verbose       (numeric, optional, default=0) If 0, return a string, other return a json object\n"

            "\nResult (if verbose is not set or set to 0):\n"
            "\"data\"      (string) The serialized, hex-encoded data for 'txid'\n"

            "\nResult (if verbose > 0):\n"
            "{\n"
            "  \"hex\" : \"data\",         (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",          (string) The transaction id (same as provided)\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"lockheight\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [                 (array of json objects)\n"
            "     {\n"
	    "       \"coinbase\" : bool,   (boolean) if input is coinbase account\n"
            "       \"pubkey\": \"key\",   (string) The public key hash of the input\n"
	    "	    \"address\" : \"addr\",(string) Cryptonite address representation of public key hash\n"
            "       \"scriptSig\": {       (json object) The script\n"
            "         \"hex\": \"hex\",    (string) hex\n"
            "       },\n"
            "       \"signed\": bool,      (boolean) if input signature is valid\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [                (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,     (ep) The value in XCN\n"
            "       \"n\" : n,             (numeric) index\n"
            "       \"pubkey\": \"key\",   (string) The public key hash of the input\n"
	    "	    \"address\" : \"addr\",(string) Cryptonite address representation of public key hash\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("getrawtransaction", "\"mytxid\"")
            + HelpExampleCli("getrawtransaction", "\"mytxid\" 1")
            + HelpExampleRpc("getrawtransaction", "\"mytxid\", 1")
        );

    uint256 hash = ParseHashV(params[0], "parameter 1");

    bool fVerbose = false;
    if (params.size() > 1)
        fVerbose = (params[1].get_int() != 0);

    CTransaction tx;
    uint256 hashBlock = 0;
    if (!GetTransaction(hash, tx, hashBlock, true))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "No information available about transaction");

    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    string strHex = HexStr(ssTx.begin(), ssTx.end());

    if (!fVerbose)
        return strHex;

    Object result;
    result.push_back(Pair("hex", strHex));
    TxToJSON(tx, hashBlock, result);
    return result;
}

#ifdef ENABLE_WALLET
Value listbalances(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2 || params.size() < 2)
        throw runtime_error(
            "listbalances ( minconf [\"address\",...] )\n"
            "\nReturns array of available spending balance\n"
            "with at least minconf confirmations.\n"
            "Results are an array of Objects, each of which has:\n"
            "{address, ours, account, balance}\n"
            "\nArguments:\n"
            "1. minconf          (numeric, optional, default=1) The minimum confirmationsi to filter\n"
            "2. \"addresses\"    (string) A json array of cryptonite addresses to filter\n"
            "    [\n"
            "      \"address\"   (string) cryptonite address\n"
            "      ,...\n"
            "    ]\n"
            "\nResult\n"
            "[                   (array of json object)\n"
            "  {\n"
            "    \"address\" : \"address\",  (string) the cryptonite address\n"
	    "    \"ours\"    : true/false,   (bool) is the account belongs to the local wallet\n"
            "    \"account\" : \"account\",  (string,null) The associated account, or \"\" for the default account\n"
            "    \"balance\" : x.xxx,        (ep) the account balance in XCN\n"
            "  }\n"
            "  ,...\n"
            "]\n"

            "\nExamples\n"
            + HelpExampleCli("listbalances", "")
            + HelpExampleCli("listbalances", "6 \"[\\\"1PGFqEzfmQch1gKD3ra4k18PNj3tTUUSqg\\\",\\\"1LtvqCaApEdUGFkpKMM4MstjcaL4dKg8SP\\\"]\"")
        );


    RPCTypeCheck(params, list_of(int_type)(array_type));

    int nMinDepth = 1;
    if (params.size() > 0){
        nMinDepth = params[0].get_int();
	if(nMinDepth > (int64_t)MIN_HISTORY || nMinDepth > (int64_t)chainActive.Height()+1)
	    throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, minconf cannot exceed min history"));
	if(nMinDepth <= 0)
	    throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, minconf cannot be <= 0"));
    }

    vector<CBitcoinAddress> vecAddress;
    vector<uint160> vecKey;
    if (params.size() > 1)
    {
        Array inputs = params[1].get_array();
        BOOST_FOREACH(Value& input, inputs)
        {
            CBitcoinAddress address(input.get_str());
            if (!address.IsValid())
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid cryptonite address: ")+input.get_str());
           vecAddress.push_back(address);
	   CKeyID foo;
	   address.GetKeyID(foo);
	   vecKey.push_back(foo);
	   //printf("Key hash: %s\n", foo.GetHex().c_str());
        }
    }


    int i;
    //TODO: this probably needs cs_Main, but rpc generally seems broken with locks
    vector<CActInfo> balances;
    pviewTip->ConservativeBalances(nMinDepth, vecKey, balances);    

    Array results;
    vector<COutput> vecOutputs;
    assert(pwalletMain != NULL);

    for(i=0; i < (int)vecAddress.size(); i++){

	Object entry;
	entry.push_back(Pair("address", vecAddress[i].ToString()));
	bool ours = pwalletMain->mapAddressBook.count(vecAddress[i].Get());
	entry.push_back(Pair("ours",ours));
	if(ours){
		entry.push_back(Pair("account",pwalletMain->mapAddressBook[vecAddress[i].Get()].name));
	}else{
		entry.push_back(Pair("account",0));
	}
	entry.push_back(Pair("balance", ValueFromAmount(balances[i].balance)));
	entry.push_back(Pair("age", balances[i].age));
	entry.push_back(Pair("limit", ValueFromAmount(balances[i].limit)));
	entry.push_back(Pair("futurelimit", ValueFromAmount(balances[i].futurelimit)));

	results.push_back(entry);
    }

    return results;
}
#endif

//sa ToDo: Update documentation
Value createrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 2 && params.size() != 3))
        throw runtime_error(
            "createrawtransaction [{\"txid\":\"id\",\"vout\":n},...] {\"address\":amount,...}\n"
            "\nCreate a transaction spending the given inputs and sending to the given addresses.\n"
            "Returns hex-encoded raw transaction.\n"
            "Note that the transaction's inputs are not signed, and\n"
            "it is not stored in the wallet or transmitted to the network.\n"

            "\nArguments:\n"
            "1. \"inputs\"        (string, required) a json object with addresses as keys and amounts as values\n"
            "    {\n"
            "      \"address\": x.xxx   (ep, required) The key is the cryptonite address, the value is the XCN amount\n"
            "      ,...\n"
            "    }\n"
            "2. \"outputs\"           (string, required) a json object with addresses as keys and amounts as values\n"
            "    {\n"
            "      \"address\": x.xxx   (ep, required) The key is the cryptonite address, the value is the XCN amount\n"
            "      ,...\n"
            "    }\n"
	    "3. \"lockheight\"    (numeric, optional) specific lockheight where transaction becomes valid. default is current chain height\n"

            "\nResult:\n"
            "\"transaction\"            (string) hex string of the transaction\n"

            "\nExamples\n"
            + HelpExampleCli("createrawtransaction", "\"{\\\"address\\\":\\\"0.01000000ep\\\",\\\"address\\\":\\\"0.01000000ep\\\"}\" \"{\\\"address\\\":\\\"0.01000000ep\\\"}\"")
            + HelpExampleRpc("createrawtransaction", "\"{\\\"address\\\":\\\"0.01000000ep\\\",\\\"address\\\":\\\"0.01000000ep\\\"}\", \"{\\\"address\\\":\\\"0.01000000ep\\\"}\"")
        );

    RPCTypeCheck(params, list_of(obj_type)(obj_type)(int_type), true);

    Object inputs = params[0].get_obj();
    Object outputs = params[1].get_obj();

    CTransaction rawTx;

    set<CBitcoinAddress> setInAddress;
    BOOST_FOREACH(const Pair& input, inputs)
    {
    	CBitcoinAddress address(input.name_);
    	if (!address.IsValid())
    		throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Cryptonite address: ")+input.name_);

		if (setInAddress.count(address))
			throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+input.name_);

		setInAddress.insert(address);

		CKeyID keyID;
		address.GetKeyID(keyID);

		int64_t nAmount = AmountFromValue(input.value_);

        CTxIn in(keyID, nAmount);
        rawTx.vin.push_back(in);
    }

    set<CBitcoinAddress> setOutAddress;
    BOOST_FOREACH(const Pair& output, outputs)
    {
        CBitcoinAddress address(output.name_);
        if (!address.IsValid())
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, string("Invalid Cryptonite address: ")+output.name_);

        if (setOutAddress.count(address))
            throw JSONRPCError(RPC_INVALID_PARAMETER, string("Invalid parameter, duplicated address: ")+output.name_);

        setOutAddress.insert(address);

        CKeyID keyID;
        address.GetKeyID(keyID);

        int64_t nAmount = AmountFromValue(output.value_);

        CTxOut out(nAmount, keyID);
        rawTx.vout.push_back(out);
    }

    if(params.size() > 2){
	rawTx.nLockHeight = params[2].get_int();
    }else{
	rawTx.nLockHeight = chainActive.Height();
    }

    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << rawTx;
    return HexStr(ss.begin(), ss.end());
}

CKeyID _createmultisig(const Array& params);

Value setuprawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 2)
        throw runtime_error(
            "setuprawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction that has been templated for multisignature signing\n"

            "\nArguments:\n"
            "1. \"txhex\"      (string, required) The transaction hex string\n"
	    "2. \"inputs\"     (string, required) JSON object with input id's as keys and multisig descriptions as values\n"
            "    {\n"
            "      \"index\":      (numeric, required) The key is the input index\n"
            "      \"multisigsetup\":  (string, required) The value is an array of multisig parameters\n"
            "      [\n"
            "        1. nrequired      (numeric, required) The number of required signatures out of the n keys or addresses.\n"
            "        2. \"keys\"       (string, required) A json array of keys which are cryptonite addresses or hex-encoded public keys\n"
            "        [\n"
            "          \"key\"    (string) cryptonite address or hex-encoded public key\n"
            "          ,...\n"
            "        ]\n"
            "      ]\n"
            "      ,...\n"
            "    }\n"
            "\n"

            "\nExamples:\n"
            + HelpExampleCli("setuprawtransaction", "\"hexstring\"")
            + HelpExampleRpc("setuprawtransaction", "\"hexstring\"")
        );

    vector<unsigned char> txData(ParseHexV(params[0], "argument"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    Object inputs = params[1].get_obj();

    set<int> indexSet;
    BOOST_FOREACH(const Pair& cinput, inputs){
	Pair input = cinput; //Copy to unconst
	Value index(input.name_);
	ConvertTo<boost::int64_t>(index);
	int idx = index.get_int();
	if(idx < 0 || idx >= (int)tx.vin.size()){
	    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Indexes out of bounds");
	}
	if(indexSet.count(idx)){
	    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Duplicate indexes");
	}
	indexSet.insert(idx);

	Value msigParms(input.value_);
	ConvertTo<Array>(msigParms);

	CKeyID key = _createmultisig(msigParms.get_array());

	if(tx.vin[idx].pubKey != key){
	    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Vin address does not match configured address");
	}

	const Array& keys = msigParms.get_array()[1].get_array();
        std::vector<uint160> keyIDs;
    	keyIDs.resize(keys.size());
    	for (unsigned int i = 0; i < keys.size(); i++)
    	{
	    const std::string& ks = keys[i].get_str();
            CBitcoinAddress address(ks);
	    CKeyID keyID;
	    address.GetKeyID(keyID);
	    keyIDs[i]=keyID;
        }
 	sort(keyIDs.begin(),keyIDs.end());
	
	char data[1+keyIDs.size()*20];
	data[0] = 0;
	for(unsigned i=0; i < keyIDs.size(); i++){
	    memcpy(&data[1+i*20],&keyIDs[i],20);
	}

	tx.vin[idx].scriptSig.clear();
	tx.vin[idx].scriptSig.assign(data,data+sizeof(data));
    }
    ssData.clear();
    ssData << tx;
    return HexStr(ssData.begin(), ssData.end());
    return Value::null;
}

Value decoderawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || (params.size() != 1 && params.size() != 2))
        throw runtime_error(
            "decoderawtransaction \"hexstring\"\n"
            "\nReturn a JSON object representing the serialized, hex-encoded transaction.\n"

            "\nArguments:\n"
            "1. \"txid\"      (string, required) The transaction hex string\n"
	    "2. \"nrequired :\" (string, optional) JSON object with mappings between inputs and the required number of signatures\n"
            "     {\n"
	    "     \"index\":\"value\"\n"
            "     }\n"

            "\nResult:\n"
           "{\n"
            "  \"hex\" : \"data\",         (string) The serialized, hex-encoded data for 'txid'\n"
            "  \"txid\" : \"id\",          (string) The transaction id (same as provided)\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"lockheight\" : ttt,       (numeric) The lock time\n"
            "  \"vin\" : [                 (array of json objects)\n"
            "     {\n"
	    "       \"coinbase\" : bool,   (boolean) if input is coinbase account\n"
            "       \"pubkey\": \"key\",   (string) The public key hash of the input\n"
	    "	    \"address\" : \"addr\",(string) Cryptonite address representation of public key hash\n"
            "       \"scriptSig\": {       (json object) The script\n"
            "         \"hex\": \"hex\",    (string) hex\n"
            "       },\n"
            "       \"signed\": bool,      (boolean) if input signature is valid\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"vout\" : [                (array of json objects)\n"
            "     {\n"
            "       \"value\" : x.xxx,     (ep) The value in XCN\n"
            "       \"n\" : n,             (numeric) index\n"
            "       \"pubkey\": \"key\",   (string) The public key hash of the input\n"
	    "	    \"address\" : \"addr\",(string) Cryptonite address representation of public key hash\n"
            "     }\n"
            "     ,...\n"
            "  ],\n"
            "  \"blockhash\" : \"hash\",   (string) the block hash\n"
            "  \"confirmations\" : n,      (numeric) The confirmations\n"
            "  \"time\" : ttt,             (numeric) The transaction time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"blocktime\" : ttt         (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("decoderawtransaction", "\"hexstring\"")
            + HelpExampleRpc("decoderawtransaction", "\"hexstring\"")
        );

    vector<unsigned char> txData(ParseHexV(params[0], "argument"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx;
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }

    map<int,int> mapSigs;
    if(params.size() > 1){
    	Object inputs = params[1].get_obj();

    	set<int> indexSet;
    	BOOST_FOREACH(const Pair& cinput, inputs){
	    Pair input = cinput; //Copy to unconst
	    Value index(input.name_);
	    ConvertTo<boost::int64_t>(index);
	    int idx = index.get_int();
	    if(idx < 0 || idx >= (int)	tx.vin.size()){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Indexes out of bounds");
	    }
	    if(indexSet.count(idx)){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Duplicate indexes");
	    }
	    indexSet.insert(idx);

	    Value reqs(input.value_);
	    ConvertTo<boost::int64_t>(reqs);
	    int reqSigs = reqs.get_int();

	    if(reqSigs < 1){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Required sigs cannot be less than one");
	    }

	    mapSigs[idx] = reqSigs;
	}
    }
    Object result;
    TxToJSON(tx, 0, result, &mapSigs);

    return result;
}

//sa ToDo: Investigate txVariants:
	//TxVariants are not included but may be useful. A new version of CombineSignatures() would need to be built.
//sa ToDo: update documentation
Value signrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 3)
        throw runtime_error(
            "signrawtransaction \"hexstring\" ( [{\"txid\":\"id\",\"vout\":n,\"scriptPubKey\":\"hex\",\"redeemScript\":\"hex\"},...] [\"privatekey1\",...] sighashtype )\n"
            "\nSign inputs for raw transaction (serialized, hex-encoded).\n"
            "The second optional argument (may be null) is an array of previous transaction outputs that\n"
            "this transaction depends on but may not yet be in the block chain.\n"
            "The third optional argument (may be null) is an array of base58-encoded private\n"
            "keys that, if given, will be the only keys used to sign the transaction.\n"
#ifdef ENABLE_WALLET
            + HelpRequiringPassphrase() + "\n"
#endif

            "\nArguments:\n"
            "1. \"hexstring\"     (string, required) The transaction hex string\n"
	    "2. \"nrequired :\" (string, optional) JSON object with mappings between inputs and the required number of signatures\n"
            "     {\n"
	    "        \"index\":\"value\"\n"
            "     }\n"
            "3. \"privatekeys\"     (string, optional) A json array of base58-encoded private keys for signing\n"
            "    [                  (json array of strings, or 'null' if none provided)\n"
            "      \"privatekey\"   (string) private key in base58-encoding\n"
            "      ,...\n"
            "    ]\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\": \"value\",   (string) The raw transaction with signature(s) (hex-encoded string)\n"
            "  \"complete\": n       (numeric) if transaction has a complete set of signature (0 if not)\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"")
            + HelpExampleRpc("signrawtransaction", "\"myhex\"")
        );

    RPCTypeCheck(params, list_of(str_type)(obj_type)(array_type), true);

    vector<unsigned char> txData(ParseHexV(params[0], "argument 1"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);

    CTransaction tx;
    if(!ssData.empty())
    {
        try {
            ssData >> tx;
        }
        catch (std::exception &e) {
            throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
        }
    }

    uint256 hash = SignatureHash(tx);

    bool fComplete = true;

    map<int,int> mapSigs;
    if(params.size() > 1 && params[1].type() != null_type){
    	Object inputs = params[1].get_obj();

    	set<int> indexSet;
    	BOOST_FOREACH(const Pair& cinput, inputs){
	    Pair input = cinput; //Copy to unconst
	    Value index(input.name_);
	    ConvertTo<boost::int64_t>(index);
	    int idx = index.get_int();
	    if(idx < 0 || idx >= (int)tx.vin.size()){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Indexes out of bounds");
	    }
	    if(indexSet.count(idx)){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Duplicate indexes");
	    }
	    indexSet.insert(idx);

	    Value reqs(input.value_);
	    ConvertTo<boost::int64_t>(reqs);
	    int reqSigs = reqs.get_int();

	    if(reqSigs < 1){
	        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Required sigs cannot be less than one");
	    }

	    mapSigs[idx] = reqSigs;
	}
    }

    bool fGivenKeys = false;
    CBasicKeyStore tempKeystore;
    if (params.size() > 2 && params[2].type() != null_type)
    {
        fGivenKeys = true;
        Array keys = params[2].get_array();
        BOOST_FOREACH(Value k, keys)
        {
            CBitcoinSecret vchSecret;
            bool fGood = vchSecret.SetString(k.get_str());
            if (!fGood)
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid private key");
            CKey key = vchSecret.GetKey();
            tempKeystore.AddKey(key);
        }
    }
#ifdef ENABLE_WALLET
    else
        EnsureWalletIsUnlocked();
#endif

#ifdef ENABLE_WALLET
    const CKeyStore& keystore = ((fGivenKeys || !pwalletMain) ? tempKeystore : *pwalletMain);
#else
    const CKeyStore& keystore = tempKeystore;
#endif

    // Sign what we can:
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        CTxIn& txin = tx.vin[i];
        CKey key;
        if(keystore.GetKey(txin.pubKey,key)){
            txin.scriptSig.clear();

            SignSignature(keystore, txin.pubKey, tx, i);
	}else{
	    //Txin is possibly multisignature if we do not have key for the hash
	    if(mapSigs.find(i) == mapSigs.end() || !txin.scriptSig.size()){
		fComplete=false;
		continue;
	    }
	    int neededSigs = mapSigs[i];
	    int currentSigs = txin.scriptSig[0];	

	    vector<uint160> recoveredKeys, explicitKeys;
	    if(!GetKeysFromSig(hash, txin.scriptSig, recoveredKeys, explicitKeys)){
		fComplete=false;
		continue;
	    }

	    for(unsigned j=0; j < explicitKeys.size(); j++){
		if(currentSigs >= neededSigs)
		    continue;

	        if(!keystore.GetKey(explicitKeys[j],key))
		    continue;
 		
		if(SignOnce(tx,hash,i,key))
		   currentSigs++;
	    }
	} 

        if (!VerifyScript(txin.scriptSig, txin.pubKey, tx, i))
            fComplete = false;
    }

    Object result;
    CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
    ssTx << tx;
    result.push_back(Pair("hex", HexStr(ssTx.begin(), ssTx.end())));
    result.push_back(Pair("complete", fComplete));

    return result;
}

//sa ToDo: Investigate allowhighfees
Value sendrawtransaction(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "sendrawtransaction \"hexstring\" ( allowhighfees )\n"
            "\nSubmits raw transaction (serialized, hex-encoded) to local node and network.\n"
            "\nAlso see createrawtransaction and signrawtransaction calls.\n"
            "\nArguments:\n"
            "1. \"hexstring\"    (string, required) The hex string of the raw transaction)\n"
            "2. allowhighfees    (boolean, optional, default=false) Allow high fees\n"
            "\nResult:\n"
            "\"hex\"             (string) The transaction hash in hex\n"
            "\nExamples:\n"
            "\nCreate a transaction\n"
            + HelpExampleCli("createrawtransaction", "\"[{\\\"txid\\\" : \\\"mytxid\\\",\\\"vout\\\":0}]\" \"{\\\"myaddress\\\":\"0.01000000ep\"}\"") +
            "Sign the transaction, and get back the hex\n"
            + HelpExampleCli("signrawtransaction", "\"myhex\"") +
            "\nSend the transaction (signed hex)\n"
            + HelpExampleCli("sendrawtransaction", "\"signedhex\"") +
            "\nAs a json rpc call\n"
            + HelpExampleRpc("sendrawtransaction", "\"signedhex\"")
        );

    // parse hex string from parameter
    vector<unsigned char> txData(ParseHexV(params[0], "parameter"));
    CDataStream ssData(txData, SER_NETWORK, PROTOCOL_VERSION);
    CTransaction tx,txFound;

    bool fOverrideFees = false;
    if (params.size() > 1)
        fOverrideFees = params[1].get_bool();

    // deserialize binary data stream
    try {
        ssData >> tx;
    }
    catch (std::exception &e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "TX decode failed");
    }
    uint256 txID = tx.GetTxID();

    uint256 block;
    bool fHave = GetTransaction(txID,txFound,block);
    bool fHaveMempool = block==0;

    if (!fHave) {
        // push to local node and sync with wallets
        CValidationState state;
        if (AcceptToMemoryPool(mempool, state, tx, false, NULL, !fOverrideFees))
            SyncWithWallets(txID, tx, NULL);
        else {
            if(state.IsInvalid())
                throw JSONRPCError(RPC_TRANSACTION_REJECTED, strprintf("%i: %s", state.GetRejectCode(), state.GetRejectReason()));
            else
                throw JSONRPCError(RPC_TRANSACTION_ERROR, state.GetRejectReason());
        }
    } else if (fHave && !fHaveMempool) {
        throw JSONRPCError(RPC_TRANSACTION_ALREADY_IN_CHAIN, "transaction already in block chain");
    }
    RelayTransaction(tx, txID);

    return txID.GetHex();
}
