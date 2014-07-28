// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CORE_H
#define BITCOIN_CORE_H

#include "script.h"
#include "serialize.h"
#include "uint256.h"

#include <stdint.h>

using namespace std;

class CTransaction;

/** No amount larger than this (in satoshi) is valid */
extern uint64_t MIN_HISTORY;
static const uint64_t MAX_MONEY = COINS * COIN;
inline bool MoneyRange(uint64_t nValue) { return nValue <= MAX_MONEY; }

/** An input of a transaction.  It contains the public key of the input, the amount to be
** transferred from the input as well as any signatures required to achieve spending
 */
class CTxIn
{
public:
    uint64_t nValue;
    uint160 pubKey;
    CScript scriptSig;

    CTxIn(CScript scriptSigIn=CScript(), unsigned int nSequenceIn=std::numeric_limits<unsigned int>::max());
    CTxIn(uint160 pubKey, uint64_t nValue);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(pubKey);
	READWRITE(nValue);
        READWRITE(scriptSig);
    )

    bool IsNull() const
    {
        return (pubKey == 0);
    }

    void SetNull()
    {
        pubKey = 0;
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.nValue   == b.nValue &&
                a.scriptSig == b.scriptSig &&
                a.pubKey == b.pubKey);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};


class CSlice {
public:
    CSlice(uint256 block, uint160 left, uint160 right, vector<uint8_t> data){
	m_block = block; m_left = left; m_right = right; m_data = data;
    }
    CSlice(uint256 block){
	m_block = block; m_left = 0; m_right = 0;
    }
    CSlice(){}

    uint256 m_block;
    uint160 m_left, m_right;
    vector<uint8_t> m_data;
    uint64_t nHeight;

    IMPLEMENT_SERIALIZE(
        READWRITE(m_block);
	READWRITE(m_left);
	READWRITE(m_right);
	READWRITE(m_data);
    )
};


/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    uint64_t nValue;
    uint160 pubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(int64_t nValueIn, uint160 pubKey);

    IMPLEMENT_SERIALIZE
    (
        READWRITE(nValue);
        READWRITE(pubKey);
    )

    void SetNull()
    {
        nValue = 0;
        pubKey = 0;
    }

    bool IsNull() const
    {
        return (nValue == 0);
    }

    uint256 GetHash() const;

#if 1
    bool IsDust(uint64_t nMinRelayTxFee) const
    {
//TODO: math all wrong here
        // "Dust" is defined in terms of CTransaction::nMinRelayTxFee,
        // which has units satoshis-per-kilobyte.
        // If you'd pay more than 1/3 in fees
        // to spend something, then we consider it dust.
        // A typical txout is 34 bytes big, and will
        // need a CTxIn of at least 148 bytes to spend,
        // so dust is a txout less than 546 satoshis 
        // with default nMinRelayTxFee.
        return ((nValue*1000)/(3*((int)GetSerializeSize(SER_DISK,0)+148)) < nMinRelayTxFee);
    }
#endif

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.pubKey == b.pubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    static int64_t nMinTxFee;
    static int64_t nMinRelayTxFee;
    static const int CURRENT_VERSION=1;
    int nVersion;
    mutable std::vector<CTxIn> vin;
    mutable std::vector<CTxOut> vout;
    std::vector<char> msg;
    uint64_t nLockHeight;
    mutable uint64_t nLimitValue;
    mutable bool fSetLimit;

    CTransaction()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
	//Do some weird serialization magic here to encode/decode the set withdrawal limit transaction
        std::vector<CTxIn> vint=vin;
        std::vector<CTxOut> voutt=vout;

	if (!fRead) {
	    //Going to write
	    if(fSetLimit){
		vint[0].nValue+=nLimitValue;
	    	voutt[0].nValue+=nLimitValue;
	    }
	}
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(vint);
        READWRITE(voutt);
	READWRITE(msg);
        READWRITE(nLockHeight);

	if(fRead){
	    if(vint.size()==1 && voutt.size()==1 && vint[0].pubKey == voutt[0].pubKey && voutt[0].nValue < vint[0].nValue){
		nLimitValue = voutt[0].nValue;
		fSetLimit=true;
		voutt[0].nValue=0;
		vint[0].nValue-=nLimitValue;
	    }
	    vin = vint;
	    vout = voutt;
	}
    )

    void SetNull()
    {
        nVersion = CTransaction::CURRENT_VERSION;
        vin.clear();
        vout.clear();
        nLockHeight = 0;
	nLimitValue = 0;
	fSetLimit=false;
    }

    bool IsNull() const
    {
        return (vin.empty() && vout.empty());
    }

    uint256 GetHash() const;
    uint256 GetTxID() const;

    bool IsNewerThan(const CTransaction& old) const;

    // Return sum of txouts.
    uint64_t GetValueOut() const;

    // Return sum of txins.
    uint64_t GetValueIn() const;

    uint64_t GetFee() const { return GetValueIn() - GetValueOut(); }

    // Compute priority, given priority of inputs and (optionally) tx size
    double ComputePriority(double dPriorityInputs, unsigned int nTxSize=0) const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return (a.nVersion  == b.nVersion &&
                a.vin       == b.vin &&
                a.vout      == b.vout &&
                a.nLockHeight == b.nLockHeight);
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
    void print() const;
};

/** wrapper for CTxOut that provides a more compact serialization */
class CTxOutCompressor
{
private:
    CTxOut &txout;

public:
    static uint64_t CompressAmount(uint64_t nAmount);
    static uint64_t DecompressAmount(uint64_t nAmount);

    CTxOutCompressor(CTxOut &txoutIn) : txout(txoutIn) { }

    IMPLEMENT_SERIALIZE(({
        if (!fRead) {
            uint64_t nVal = CompressAmount(txout.nValue);
            READWRITE(VARINT(nVal));
        } else {
            uint64_t nVal = 0;
            READWRITE(VARINT(nVal));
            txout.nValue = DecompressAmount(nVal);
        }
        READWRITE(txout.pubKey);
    });)
};


/** Nodes collect new transactions into a block, hash them into a hash tree,
 * and scan through nonce values to make the block's hash satisfy proof-of-work
 * requirements.  When they solve the proof-of-work, they broadcast the block
 * to everyone and the block is added to the block chain.  The first transaction
 * in the block is a special one that creates a new coin owned by the creator
 * of the block.
 */
#pragma pack(push,1)
class CBlockHeader
{
public:
    // header
    static const int CURRENT_VERSION=1;

    //!!!!!!!!!!! struct must be in packed order even though serialize order is version first
    //or else we can't use hash macros, could also use #pragma pack but that has 
    //terrible implicatation on non-x86
    uint256 hashPrevBlock;
    uint256 hashMerkleRoot;
    uint256 hashAccountRoot;
    uint64_t nTime;
    uint64_t nHeight;
    uint64_t nNonce;
    uint16_t nVersion;

    CBlockHeader()
    {
        SetNull();
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(this->nVersion);
        nVersion = this->nVersion;
        READWRITE(hashPrevBlock);
        READWRITE(hashMerkleRoot);
	READWRITE(hashAccountRoot);
        READWRITE(nTime);
	READWRITE(nHeight);
        READWRITE(nNonce);
    )

    void SetNull()
    {
        nVersion = CBlockHeader::CURRENT_VERSION;
        hashPrevBlock = 0;
        hashMerkleRoot = 0;
	hashAccountRoot = 0;
        nTime = 0;
        nNonce = 0;
	nHeight = 0;
    }

    uint256 GetHash() const;

    int64_t GetBlockTime() const
    {
        return (int64_t)nTime;
    }
};


class CBlock : public CBlockHeader
{
public:
    // network and disk
    std::vector<CTransaction> vtx;

    // memory only
    mutable std::vector<uint256> vMerkleTree;

    CBlock()
    {
        SetNull();
    }

    CBlock(const CBlockHeader &header)
    {
        SetNull();
        *((CBlockHeader*)this) = header;
    }

    IMPLEMENT_SERIALIZE
    (
        READWRITE(*(CBlockHeader*)this);
        READWRITE(vtx);
    )

    void SetNull()
    {
        CBlockHeader::SetNull();
        vtx.clear();
        vMerkleTree.clear();
    }

    CBlockHeader GetBlockHeader() const
    {
        CBlockHeader block;
        block.nVersion       = nVersion;
        block.hashPrevBlock  = hashPrevBlock;
        block.hashMerkleRoot = hashMerkleRoot;
	block.hashAccountRoot= hashAccountRoot;
        block.nTime          = nTime;
        block.nNonce         = nNonce;
	block.nHeight	     = nHeight;
        return block;
    }

    uint64_t GetFees(){
	uint64_t ret=0;
	BOOST_FOREACH(CTransaction tx, vtx){
	   ret+=tx.GetFee();
	}
	return ret;
    }

    uint256 BuildMerkleTree() const;

    const uint256 &GetTxHash(unsigned int nIndex) const {
        assert(vMerkleTree.size() > 0); // BuildMerkleTree must have been called first
        assert(nIndex < vtx.size());
        return vMerkleTree[nIndex];
    }

    std::vector<uint256> GetMerkleBranch(int nIndex) const;
    static uint256 CheckMerkleBranch(uint256 hash, const std::vector<uint256>& vMerkleBranch, int nIndex);
    void print() const;
};
#pragma pack(pop)


/** Describes a place in the block chain to another node such that if the
 * other node doesn't have the same branch, it can find a recent common trunk.
 * The further back it is, the further before the fork it may be.
 */
struct CBlockLocator
{
    std::vector<uint256> vHave;

    CBlockLocator() {}

    CBlockLocator(const std::vector<uint256>& vHaveIn)
    {
        vHave = vHaveIn;
    }

    IMPLEMENT_SERIALIZE
    (
        if (!(nType & SER_GETHASH))
            READWRITE(nVersion);
        READWRITE(vHave);
    )

    void SetNull()
    {
        vHave.clear();
    }

    bool IsNull()
    {
        return vHave.empty();
    }
};

#endif
