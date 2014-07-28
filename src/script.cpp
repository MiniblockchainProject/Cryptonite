// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "script.h"

#include "bignum.h"
#include "core.h"
#include "hash.h"
#include "key.h"
#include "keystore.h"
#include "sync.h"
#include "uint256.h"
#include "util.h"

#include <boost/foreach.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>

using namespace std;
using namespace boost;

typedef vector<unsigned char> valtype;

const char* GetTxnOutputType(txnouttype t)
{
    switch (t)
    {
    case TX_NONSTANDARD: return "nonstandard";
    case TX_PUBKEY: return "pubkey";
    case TX_PUBKEYHASH: return "pubkeyhash";
    case TX_SCRIPTHASH: return "scripthash";
    case TX_MULTISIG: return "multisig";
    case TX_NULL_DATA: return "nulldata";
    }
    return NULL;
}

namespace {
/** Wrapper that serializes like CTransaction, but with the modifications
 *  required for the signature hash done in-place
 */
class CTransactionSignatureSerializer {
private:
    const CTransaction &txTo;  // reference to the spending transaction (the one being serialized)

public:
    CTransactionSignatureSerializer(const CTransaction &txToIn) :
        txTo(txToIn) {}

    /** Serialize an input of txTo */
    template<typename S>
    void SerializeInput(S &s, unsigned int nInput, int nType, int nVersion) const {
        // Serialize the prevout
        ::Serialize(s, txTo.vin[nInput].pubKey, nType, nVersion);
	::Serialize(s, txTo.vin[nInput].nValue, nType, nVersion);
    }

    /** Serialize an output of txTo */
    template<typename S>
    void SerializeOutput(S &s, unsigned int nOutput, int nType, int nVersion) const {
        ::Serialize(s, txTo.vout[nOutput], nType, nVersion);
    }

    /** Serialize txTo */
    template<typename S>
    void Serialize(S &s, int nType, int nVersion) const {
        // Serialize nVersion
        ::Serialize(s, txTo.nVersion, nType, nVersion);
        // Serialize vin
        unsigned int nInputs = txTo.vin.size();
        ::WriteCompactSize(s, nInputs);
        for (unsigned int nInput = 0; nInput < nInputs; nInput++)
             SerializeInput(s, nInput, nType, nVersion);
        // Serialize vout
        unsigned int nOutputs = txTo.vout.size();
        ::WriteCompactSize(s, nOutputs);
        for (unsigned int nOutput = 0; nOutput < nOutputs; nOutput++)
             SerializeOutput(s, nOutput, nType, nVersion);
	// Serialize msg
	::WriteCompactSize(s, txTo.msg.size());
	::Serialize(s, txTo.msg, nType, nVersion);
        // Serialie nLockTime
        ::Serialize(s, txTo.nLockHeight, nType, nVersion);
    }
};
}

uint256 SignatureHash(const CTransaction& txTo)
{
    // Wrapper to serialize only the necessary parts of the transaction being signed
    CTransactionSignatureSerializer txTmp(txTo);

    // Serialize and hash
    CHashWriter ss(SER_GETHASH, 0);
    ss << txTmp;
    return ss.GetHash();
}


// Valid signature cache, to avoid doing expensive ECDSA signature checking
// twice for every transaction (once when accepted into memory pool, and
// again when accepted into the block chain)

class CSignatureCache
{
private:
     // sigdata_type is (signature hash, signature, public key):
    typedef boost::tuple<uint256, std::vector<unsigned char>, CPubKey> sigdata_type;
    std::set< sigdata_type> setValid;
    boost::shared_mutex cs_sigcache;

public:
    bool
    Get(const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubKey)
    {
        boost::shared_lock<boost::shared_mutex> lock(cs_sigcache);

        sigdata_type k(hash, vchSig, pubKey);
        std::set<sigdata_type>::iterator mi = setValid.find(k);
        if (mi != setValid.end())
            return true;
        return false;
    }

    void Set(const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubKey)
    {
        // DoS prevention: limit cache size to less than 10MB
        // (~200 bytes per cache entry times 50,000 entries)
        // Since there are a maximum of 20,000 signature operations per block
        // 50,000 is a reasonable default.
        int64_t nMaxCacheSize = GetArg("-maxsigcachesize", 50000);
        if (nMaxCacheSize <= 0) return;

        boost::unique_lock<boost::shared_mutex> lock(cs_sigcache);

        while (static_cast<int64_t>(setValid.size()) > nMaxCacheSize)
        {
            // Evict a random entry. Random because that helps
            // foil would-be DoS attackers who might try to pre-generate
            // and re-use a set of valid signatures just-slightly-greater
            // than our cache size.
            uint256 randomHash = GetRandHash();
            std::vector<unsigned char> unused;
            std::set<sigdata_type>::iterator it =
                setValid.lower_bound(sigdata_type(randomHash, unused, unused));
            if (it == setValid.end())
                it = setValid.begin();
            setValid.erase(*it);
        }

        sigdata_type k(hash, vchSig, pubKey);
        setValid.insert(k);
    }
};

bool Sign1(const CKeyID& address, const CKeyStore& keystore, uint256 hash, CScript& scriptSigRet)
{
    CKey key;
    if (!keystore.GetKey(address, key))
        return false;

    vector<unsigned char> vchSig;
    if (!key.SignCompact(hash, vchSig))
        return false;
    scriptSigRet << vchSig;

    //printf("Size: %ld %ld\n", scriptSigRet.size(), vchSig.size());

    return true;
}

bool SignN(const vector<valtype>& multisigdata, const CKeyStore& keystore, uint256 hash, CScript& scriptSigRet)
{
    int nSigned = 0;
    int nRequired = multisigdata.front()[0];
    for (unsigned int i = 1; i < multisigdata.size()-1 && nSigned < nRequired; i++)
    {
        const valtype& pubkey = multisigdata[i];
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (Sign1(keyID, keystore, hash, scriptSigRet))
            ++nSigned;
    }
    return nSigned==nRequired;
}

unsigned int HaveKeys(const vector<valtype>& pubkeys, const CKeyStore& keystore)
{
    unsigned int nResult = 0;
    BOOST_FOREACH(const valtype& pubkey, pubkeys)
    {
        CKeyID keyID = CPubKey(pubkey).GetID();
        if (keystore.HaveKey(keyID))
            ++nResult;
    }
    return nResult;
}

bool VerifyScript(const CScript& scriptSig, const uint160& pubKey, const CTransaction& txTo, unsigned int nIn)
{
    assert(nIn < txTo.vin.size());
    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(txTo);
    //cout << "Tx Hash: " << hash.GetHex() << endl;
    //cout << "Key: " << pubKey.GetHex() << endl;
    bool found=false;
    BOOST_FOREACH(const CTxIn &txin, txTo.vin){
	if(txin.pubKey!=pubKey)
	    continue;
#if 0
	printf("Size: %ld\n", txin.scriptSig.size());
	for(int i=0; i < txin.scriptSig.size(); i++){
		printf("%2.2X", txin.scriptSig[i]);
	}
	printf("\n");
#endif
	if(!txin.scriptSig.size())
	    return false;

	//Signature format is 1 byte for number of signatures.
	//Signatures are 65 bytes each
	//Public hashs of (m-n) of m are 20 bytes
	uint32_t nSigs = txin.scriptSig[0];
	if(!nSigs)
	    return false;

	uint32_t nHashStart = nSigs*65 + 1;

	if(txin.scriptSig.size() < nHashStart)
	    return false;

	uint32_t nHashArea = txin.scriptSig.size() - nHashStart;
	if(nHashArea%20)
	    return false;

	uint32_t nHashSigs = nHashArea/20;

	CPubKey key;
    	vector<uint160> recoveredKeys;
	for(uint32_t i=0; i < nSigs; i++){
	    if(!key.RecoverCompact(hash,&txin.scriptSig[1+i*65])){
		printf("Could not recover key\n");
		return false;
	    }
	    recoveredKeys.push_back(key.GetID());
	}

	vector<uint160> explicitKeys;
	for(uint32_t i=0; i < nHashSigs; i++){
	    uint160 temp;
	    memcpy(&temp, &txin.scriptSig[nHashStart + i * 20], 20);
	    explicitKeys.push_back(temp);
	}
        
	//printf("Recovered: %s for %s\n", recoveredKeys[0].GetHex().c_str(), pubKey.GetHex().c_str());

	//We must enforce that the keys are sorted in order to remove malleability
	if(!is_sorted(recoveredKeys.begin(),recoveredKeys.end()))
	    return false;

	if(!is_sorted(explicitKeys.begin(),explicitKeys.end()))
	    return false;

	//combine the vectors
	vector<uint160> allKeys;
	allKeys.insert(allKeys.end(), recoveredKeys.begin(), recoveredKeys.end());
	allKeys.insert(allKeys.end(), explicitKeys.begin(), explicitKeys.end());

	//Special case for single sigs
	if(nSigs==1 && nHashSigs==0){
	    //printf("RecoveredKeys:s %lu\n", recoveredKeys.size());
	    if(recoveredKeys[0] != pubKey){
		printf("Fail!!!!\n");
		return false;
	    }
	    found=true;
	    continue;
	}

	//Sort the complete key collection
	sort(allKeys.begin(),allKeys.end());
	char data[allKeys.size()*20 + 1];
	for(uint32_t i=0; i < allKeys.size(); i++){
	    memcpy(&data[i*20],&allKeys[i],20);
	}
	data[sizeof(data)-1] = nSigs;

	uint160 hash = Hash160(data,data+sizeof(data));	
	if(hash!=pubKey){
	    printf("Multisig fail\n");
	    return false;
	}
	found=true;
    }
    return found;
}

bool SignSignature(const CKeyStore &keystore, uint160 pubKey, CTransaction& txTo, uint32_t nIn)
{
    assert(nIn < txTo.vin.size());
    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.
    uint256 hash = SignatureHash(txTo);
    //cout << "Tx Hash: " << hash.GetHex() << endl;
    //cout << "Key: " << pubKey.GetHex() << endl;
    BOOST_FOREACH(CTxIn &txin, txTo.vin){
	if(txin.pubKey!=pubKey)
	    continue;
	txin.scriptSig.push_back(1);
	return Sign1(CKeyID(pubKey),keystore,hash,txin.scriptSig);
    }
    return false;
}
void CScript::SetMultisig(int nRequired, const std::vector<CPubKey>& keys)
{
#if 0
    this->clear();

    *this << EncodeOP_N(nRequired);
    BOOST_FOREACH(const CPubKey& key, keys)
        *this << key;
    *this << EncodeOP_N(keys.size()) << OP_CHECKMULTISIG;
#else
   assert(0);
#endif
}


