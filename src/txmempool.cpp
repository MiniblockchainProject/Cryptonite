// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2013 The Bitcoin developers
// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "core.h"
#include "txmempool.h"

using namespace std;

CTxMemPoolEntry::CTxMemPoolEntry()
{
    nHeight = MEMPOOL_HEIGHT;
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTransaction& _tx, int64_t _nFee,
                                 int64_t _nTime, double _dPriority,
                                 unsigned int _nHeight):
    tx(_tx), nFee(_nFee), nTime(_nTime), dPriority(_dPriority), nHeight(_nHeight)
{
    nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
}

CTxMemPoolEntry::CTxMemPoolEntry(const CTxMemPoolEntry& other)
{
    *this = other;
}

double
CTxMemPoolEntry::GetPriority(unsigned int currentHeight) const
{
    int64_t nValueIn = tx.GetValueOut()+nFee;
    double deltaPriority = ((double)(currentHeight-nHeight)*nValueIn)/nTxSize;
    double dResult = dPriority + deltaPriority;
    return dResult;
}

CTxMemPool::CTxMemPool()
{
    // Sanity checks off by default for performance, because otherwise
    // accepting transactions becomes O(N^2) where N is the number
    // of transactions in the pool
    fSanityCheck = false;
}

unsigned int CTxMemPool::GetTransactionsUpdated() const
{
    LOCK(cs);
    return nTransactionsUpdated;
}

void CTxMemPool::AddTransactionsUpdated(unsigned int n)
{
    LOCK(cs);
    nTransactionsUpdated += n;
}


bool CTxMemPool::addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry)
{
    // Add to memory pool without checking anything.
    // Used by main.cpp AcceptToMemoryPool(), which DOES do
    // all the appropriate checks.
    LOCK(cs);
    {
	LogPrintf("addUnchecked %s\n", hash.GetHex().c_str());
        mapTx[hash] = entry;
        CTransaction tx = mapTx[hash].GetTx();
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapAccount[tx.vin[i].pubKey][tx.GetTxID()] = tx;
	for (unsigned int i = 0; i < tx.vout.size(); i++)
            mapAccount[tx.vout[i].pubKey][tx.GetTxID()] = tx;
        nTransactionsUpdated++;	
	if(tx.fSetLimit){
	    if(mapLimits.find(tx.vin[0].pubKey) == mapLimits.end())
		mapLimits[tx.vin[0].pubKey] = 1;
	    else
		mapLimits[tx.vin[0].pubKey]++;
	}	
    }
    return true;
}


void CTxMemPool::remove(const CTransaction &tx)
{
    // Remove transaction from memory pool
    // TODO: this is actually much more complex. other transactions in the pool
    // may rely on outputs from a completed transaction. 
    // also multiple transactions may use an account for input/output
    LOCK(cs);
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            mapAccount[txin.pubKey].erase(tx.GetTxID());
        BOOST_FOREACH(const CTxOut& txout, tx.vout)
            mapAccount[txout.pubKey].erase(tx.GetTxID());
        mapTx.erase(tx.GetTxID());
        nTransactionsUpdated++;

	if(tx.fSetLimit && mapLimits.find(tx.vin[0].pubKey) != mapLimits.end()){
	    int limit = mapLimits[tx.vin[0].pubKey];
	    if(limit==1)
		mapLimits.erase(tx.vin[0].pubKey);
	    else
		mapLimits[tx.vin[0].pubKey]--;
	}
    }
}

int CTxMemPool::numLimits(uint160 key){
    if(mapLimits.find(key) != mapLimits.end())
	return mapLimits[key];
    return 0;
}

void CTxMemPool::validate(std::vector<CTransaction>& removed){
    LOCK(cs);

    map<uint160,uint64_t> mapBalances;
    for (map<uint256, CTxMemPoolEntry>::iterator mi = mapTx.begin();
             mi !=mapTx.end(); ++mi)
    {
	//printf("Analyzing tx\n");
        const CTransaction& tx = mi->second.GetTx();
        if (tx.IsCoinBase())
	    continue;
	if(!IsFinalTx(tx, chainActive.Height()+5)){ //Fudge the height a bunch here to prevent height skew from fubarring things
	    printf("Transaction not final %s %ld %ld\n", tx.GetTxID().GetHex().c_str(), tx.nLockHeight, chainActive.Height());
	    removed.push_back(tx);
            continue;
	}

        bool fMissingInputs = false;
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
        {
	    //printf("Analyzing txin\n");
	    if(mapBalances.find(txin.pubKey)!=mapBalances.end()){
		uint64_t balance = mapBalances[txin.pubKey];
		if(balance < txin.nValue){
		    fMissingInputs=true;
		    break;
		}
		mapBalances[txin.pubKey] -= txin.nValue;
	    }else{
		uint64_t balance=0;
		if(!pviewTip->Balance(txin.pubKey,balance)){
		    fMissingInputs=true;
		    break;
		}
		uint64_t limit=0;
		pviewTip->Limit(txin.pubKey,limit,chainActive.Height());
		if(limit < balance)
		    balance = limit;
		if(balance < txin.nValue){
		    fMissingInputs=true;
		    break;
		}
		mapBalances[txin.pubKey] = balance - txin.nValue;
	    }
        }

	bool fMissingOutputs=false;
	BOOST_FOREACH(const CTxOut& txout, tx.vout){
	    uint64_t balance=0;
	    if(!pviewTip->Balance(txout.pubKey,balance)){
		if(txout.nValue < tx.GetFee()){
		    fMissingOutputs=true;
		}
	    }
	}

        if (fMissingInputs || fMissingOutputs || TxExists(tx.GetTxID())){ 
	    printf("Transaction missing something %s %d %d %d\n", tx.GetTxID().GetHex().c_str(), fMissingInputs, fMissingOutputs, TxExists(tx.GetTxID()));
	    removed.push_back(tx);
	}
    }
    BOOST_FOREACH(CTransaction tx, removed){
	remove(tx);
    }
}

void CTxMemPool::removeConflicts(const CTransaction &tx, std::list<CTransaction>& removed)
{
   //TODO: conflicts have a new meaning now. we want to check balance on all tx.vin
   //and make sure no transactions in mempool are for larger than available balance
    // Remove transactions which depend on inputs of tx, recursively
#if 0
    list<CTransaction> result;
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
            {
                remove(txConflict, removed, true);
            }
        }
    }
#endif
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapAccount.clear();
    ++nTransactionsUpdated;
}


void CTxMemPool::queryHashes(vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTxMemPoolEntry>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}

bool CTxMemPool::lookup(uint256 hash, CTransaction& result) const
{
    LOCK(cs);
    map<uint256, CTxMemPoolEntry>::const_iterator i = mapTx.find(hash);
    if (i == mapTx.end()) return false;
    result = i->second.GetTx();
    return true;
}

bool CTxMemPool::lookup(uint160 hash, vector<CTransaction> &result) const
{
    LOCK(cs);
    map<uint160, map<uint256, CTransaction> >::const_iterator i = mapAccount.find(hash);
    if (i == mapAccount.end()) return false;
    map<uint256, CTransaction>::const_iterator it;
    for(it = i->second.begin(); it!= i->second.end(); it++)
	result.push_back(it->second);
    return true;
}

