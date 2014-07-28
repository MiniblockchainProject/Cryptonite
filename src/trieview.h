// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRIEVIEW_H
#define TRIEVIEW_H

#include "trie.h"

class CTxUndo {
public:
    CTxUndo(){}
    CTxUndo(uint160 key){
	m_key = key; m_balance = 0; m_age = 0; 
	m_limit = 0; m_futurelimit = 0;
	m_create = false; m_destroy = false;
    }

    uint160 m_key;
    uint64_t m_balance;
    uint64_t m_age;
    uint64_t m_limit;
    uint64_t m_futurelimit;
    bool m_create;
    bool m_destroy;

    IMPLEMENT_SERIALIZE(
        READWRITE(m_key);
	READWRITE(m_balance);
	READWRITE(m_age);
	READWRITE(m_limit);
	READWRITE(m_futurelimit);
	READWRITE(m_create);
	READWRITE(m_destroy);
    )
};

class CActInfo {
public:
    CActInfo(uint64_t b){
	balance = b; age=0; limit=0; futurelimit=0;
    }

    CActInfo(uint64_t b, uint64_t a, uint64_t l, uint64_t f){
	balance = b; age = a; limit = l; futurelimit = f;
    }

    CActInfo(){
	balance=0; age=0; limit=0; futurelimit=0;
    }	

    CActInfo(TrieNode *node){
	balance = node->Balance();
	age = node->Age();
	limit = node->Limit();
	futurelimit = node->FutureLimit();
    }

    uint64_t balance, age, limit, futurelimit;
};

class TrieView {
public:
    TrieView();
 
    void Force(TrieNode* root, uint256 hash);
    bool Flush();
    uint256 GetBestBlock() { return m_bestBlock;} 
    bool HaveInputs(const CTransaction &tx) { return true; }
    bool SetBestBlock(uint256) { return true; }
    bool Activate(CBlockIndex* pindex, uint256 &badBlock); 
    bool Balance(uint160 key, uint64_t &balance);
    bool Limit(uint160 key, uint64_t &limit, uint64_t height);
    bool BalancesAt(CBlockIndex* pindex, vector<uint160> hashes, vector<CActInfo> &balances);
    bool ConservativeBalances(int nMinConf, vector<uint160> hashes, vector<CActInfo> &balances);
    bool ComplexBalances(int nMineConf, int nTheirsConf, vector<uint160> hashes, vector<CActInfo> &balances);
    uint64_t Accounts();
    uint64_t CoinAge(uint160 pubKey);
    bool HashForBlock(CBlock block, uint256 &hash);
    uint32_t GetSlice(uint256 block, uint160 left, uint160 right, uint8_t *buf, uint32_t sz, uint32_t *nodes);

private:
    bool TempApply(CBlock block, list<CTxUndo> &undos);
    bool Unapply(list<CTxUndo> &undos);

    uint256 m_bestBlock;
    bool Apply(CBlockIndex *pindex);
    TrieNode *m_root;
};

#endif //TRIEVIEW_H
