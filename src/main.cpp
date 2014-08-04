// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"

#include "addrman.h"
#include "alert.h"
#include "chainparams.h"
#include "checkpoints.h"
#include "checkqueue.h"
#include "init.h"
#include "net.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"

#include <sys/types.h>
#include <sstream>

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

#include <gmpxx.h>

using namespace std;
using namespace boost;

#if defined(NDEBUG)
# error "Cryptonite cannot be compiled without assertions."
#endif

double __ieee754_pow(double x, double y);

//
// Global state
//

CCriticalSection cs_main;

CTxMemPool mempool;

map<uint256, CBlockIndex*> mapBlockIndex;
map<uint64_t, CBlockIndex*> mapBlockByHeight;
map<uint256, double> mapDifficulty;
CChain chainActive;
CChain chainHeaders;
CBlockCache blockCache;
TrieSync trieSync;
int64_t nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fBenchmark = false;
bool fLoading = false;
bool fTxIndex = true;
bool fNeedsResync = false;
bool fTrieOnline = false;
bool fValidating = false;
unsigned int nCoinCacheSize = 5000;
bool ForceNoTrie();
set<NodeId> AllNodes();
CConditionVariable cvBlockChange;

/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
int64_t CTransaction::nMinTxFee = 1000;  // Override with -mintxfee
/** Fees smaller than this (in satoshi) are considered zero fee (for relaying and mining) */
int64_t CTransaction::nMinRelayTxFee = 1000;

uint64_t MIN_HISTORY = 1000;

static std::set<int> setHeightMissing; // All heights that are > pindexBest, <= pindexBestHeight, <= pindexBest+MAX_BLOCKS_IN_TRANSIT, and not requested from peers.
static std::map<CBlockIndex*, uint64_t> mapBlocksAskedFor;
static map<NodeId, set<uint256> > setBlockDontHave;

struct COrphanBlock {
    uint256 hashBlock;
    uint256 hashPrev;
    vector<unsigned char> vchBlock;
};

void static UpdateMissingHeight();
bool static LinkOrphans(const uint256 *phashParent=NULL);

// multimap with orphan entries in the block index, indexed by their hashPrev.
// This is only used for dealing with out-of-order blocks in imported block files,
// not for dealing with orphans received from the network.
static std::multimap<uint256, CBlockIndex*> mapOrphanBlocksByPrev;
static std::multimap<uint256, uint256> mapUnindexedByPrev;
static std::map<uint256, CBlock*> mapUnindexed;

const string strMessageMagic = "Cryptonite Signed Message:\n";

// Internal stuff
namespace {
struct CBlockIndexWorkComparator
{
    bool operator()(CBlockIndex *pa, CBlockIndex *pb) {
        // First sort by most total work, ...
        if (pa->nChainWork > pb->nChainWork) return false;
        if (pa->nChainWork < pb->nChainWork) return true;

        // ... then by earliest time received, ...
        if (pa->nSequenceId < pb->nSequenceId) return false;
        if (pa->nSequenceId > pb->nSequenceId) return true;

        // Use pointer address as tie breaker (should only happen with blocks
        // loaded from disk, as those all have id 0).
        if (pa < pb) return false;
        if (pa > pb) return true;

        // Identical blocks.
        return false;
    }
};

CBlockIndex *pindexBestInvalid;
CBlockIndex *pindexGenesisBlock;
CBlockIndex *pindexSyncPoint;
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed


void printAffairs(){
 	printf("activeHeight: %ld, headersHeight: %ld\n", chainActive.Height(), chainHeaders.Height());
	printf("indexSize: %ld, orphansSize: %ld\n", mapBlockIndex.size(), mapOrphanBlocksByPrev.size());
	printf("askedSize: %ld, missingSize: %ld\n", mapBlocksAskedFor.size(), setHeightMissing.size());
	printf("validSize: %ld\n", setBlockIndexValid.size());
}


CCriticalSection cs_LastBlockFile;
CBlockFileInfo infoLastBlockFile;
int nLastBlockFile = 0;

// Every received block is assigned a unique and increasing identifier, so we
// know which one to give priority in case of a fork.
CCriticalSection cs_nBlockSequenceId;
// Blocks loaded from disk are assigned id 0, so start the counter at 1.
uint32_t nBlockSequenceId = 1;

// Sources of received blocks, to be able to send them reject messages or ban
// them, if processing happens afterwards. Protected by cs_main.
map<uint256, NodeId> mapBlockSource;

}

/** Show progress e.g. for load */
boost::signals2::signal<void (const std::string &title, int nProgress)> ShowProgress;


//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

namespace {
struct CMainSignals {
    // Notifies listeners of updated transaction data (passing hash, transaction, and optionally the block it is found in.
    boost::signals2::signal<void (const uint256 &, const CTransaction &, const CBlock *)> SyncTransaction;
    // Notifies listeners of an erased transaction (currently disabled, requires transaction replacement).
    boost::signals2::signal<void (const uint256 &)> EraseTransaction;
    // Notifies listeners of an updated transaction without new data (for now: a coinbase potentially becoming visible).
    boost::signals2::signal<void (const uint256 &)> UpdatedTransaction;
    // Notifies listeners of a new active block chain.
    boost::signals2::signal<void (const CBlockLocator &)> SetBestChain;
    // Notifies listeners about an inventory item being seen on the network.
    boost::signals2::signal<void (const uint256 &)> Inventory;
    // Tells listeners to broadcast their data.
    boost::signals2::signal<void ()> Broadcast;
} g_signals;
}

void RegisterWallet(CWalletInterface* pwalletIn) {
    g_signals.SyncTransaction.connect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3));
    g_signals.EraseTransaction.connect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.UpdatedTransaction.connect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.SetBestChain.connect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.Inventory.connect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.Broadcast.connect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn));
}

void UnregisterWallet(CWalletInterface* pwalletIn) {
    g_signals.Broadcast.disconnect(boost::bind(&CWalletInterface::ResendWalletTransactions, pwalletIn));
    g_signals.Inventory.disconnect(boost::bind(&CWalletInterface::Inventory, pwalletIn, _1));
    g_signals.SetBestChain.disconnect(boost::bind(&CWalletInterface::SetBestChain, pwalletIn, _1));
    g_signals.UpdatedTransaction.disconnect(boost::bind(&CWalletInterface::UpdatedTransaction, pwalletIn, _1));
    g_signals.EraseTransaction.disconnect(boost::bind(&CWalletInterface::EraseFromWallet, pwalletIn, _1));
    g_signals.SyncTransaction.disconnect(boost::bind(&CWalletInterface::SyncTransaction, pwalletIn, _1, _2, _3));
}

void UnregisterAllWallets() {
    g_signals.Broadcast.disconnect_all_slots();
    g_signals.Inventory.disconnect_all_slots();
    g_signals.SetBestChain.disconnect_all_slots();
    g_signals.UpdatedTransaction.disconnect_all_slots();
    g_signals.EraseTransaction.disconnect_all_slots();
    g_signals.SyncTransaction.disconnect_all_slots();
}

void SyncWithWallets(const uint256 &hash, const CTransaction &tx, const CBlock *pblock) {
    g_signals.SyncTransaction(hash, tx, pblock);
}

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace {

struct CBlockReject {
    unsigned char chRejectCode;
    string strRejectReason;
    uint256 hashBlock;
};

// Maintain validation-specific state about nodes, protected by cs_main, instead
// by CNode's own locks. This simplifies asynchronous operation, where
// processing of incoming data is done after the ProcessMessage call returns,
// and we're no longer holding the node's locks.
struct CNodeState {
    // Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    // Whether this peer should be disconnected and banned.
    bool fShouldBan;
    // String name of this peer (debugging/logging purposes).
    std::string name;
    // List of asynchronously-determined block rejections to notify this peer about.
    std::vector<CBlockReject> rejects;
    int64_t nLastBlockReceive;
    int64_t nLastBlockProcess;

    CNodeState() {
        nMisbehavior = 0;
        fShouldBan = false;
        nLastBlockReceive = 0;
        nLastBlockProcess = 0;
    }
};

// Map maintaining per-node state. Requires cs_main.
map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode) {
    map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

int GetHeight()
{
    LOCK(cs_main);
    return chainActive.Height();
}


void InitializeNode(NodeId nodeid, const CNode *pnode) {
    LOCK(cs_main);
    CNodeState &state = mapNodeState.insert(std::make_pair(nodeid, CNodeState())).first->second;
    state.name = pnode->addrName;
}

void FinalizeNode(NodeId nodeid, const CNode *pnode) {
    LOCK(cs_main);
    {
	LOCK(cs_main);
        setBlockDontHave.erase(nodeid);
	printf("Finalize Node\n");

     	BOOST_FOREACH(CBlockIndex *pindex, pnode->setBlocksAskedFor) {
            mapBlocksAskedFor.erase(pindex);
	    mapAlreadyAskedFor.erase(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            UpdateMissingHeight();
	}
    }
	
    mapNodeState.erase(nodeid);

    if(pnode->fSliced)
	trieSync.AbortSlice(pnode->slice,false, AllNodes(), nodeid);
    if(mapNodeState.size()==0)
	trieSync.Reset(); //Abort all slices and log2 shits if everybody dropped us
}
}

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    return true;
}

void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.connect(&GetHeight);
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.GetHeight.disconnect(&GetHeight);
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}

//////////////////////////////////////////////////////////////////////////////
//
// CChain implementation
//

CBlockIndex *CChain::SetTip(CBlockIndex *pindex) {
    if (pindex == NULL) {
        vChain.clear();
        return NULL;
    }
    vChain.resize(pindex->nHeight + 1);
    while (pindex && vChain[pindex->nHeight] != pindex) {
        vChain[pindex->nHeight] = pindex;
        pindex = pindex->pprev;
    }
    return pindex;
}

CBlockLocator CChain::GetLocator(const CBlockIndex *pindex) const {
    int nStep = 1;
    std::vector<uint256> vHave;
    vHave.reserve(32);

    if (!pindex)
        pindex = Tip();
    while (pindex) {
        vHave.push_back(pindex->GetBlockHash());
        // Stop when we have added the genesis block.
        if (pindex->nHeight == 0)
            break;
        // Exponentially larger steps back, plus the genesis block.
        int nHeight = std::max((int)pindex->nHeight - nStep, 0);
        // In case pindex is not in this chain, iterate pindex->pprev to find blocks.
        while (pindex->nHeight > nHeight && !Contains(pindex))
            pindex = pindex->pprev;
        // If pindex is in this chain, use direct height-based access.
        if (pindex->nHeight > nHeight)
            pindex = (*this)[nHeight];
        if (vHave.size() > 10)
            nStep *= 2;
    }

    return CBlockLocator(vHave);
}

CBlockIndex *CChain::FindFork(const CBlockLocator &locator) const {
    // Find the first block the caller has in the main chain
    BOOST_FOREACH(const uint256& hash, locator.vHave) {
        std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (Contains(pindex))
                return pindex;
        }
    }
    return Genesis();
}

CBlockIndex *CChain::FindFork(CBlockIndex *pindex) const {
    while (pindex && !Contains(pindex))
        pindex = pindex->pprev;
    return pindex;
}

TrieView *pviewTip = NULL;
CBlockTreeDB *pblocktree = NULL;

bool IsFinalTx(const CTransaction &tx, int nBlockHeight, int64_t nBlockTime)
{
    if (nBlockHeight == 0)
        nBlockHeight = chainActive.Height();
    if( nBlockHeight < 0)
	nBlockHeight = 0;
    if ((int64_t)tx.nLockHeight > nBlockHeight){
//	printf("Too far in future! %ld %ld\n", tx.nLockHeight, nBlockHeight);
	return false;
    }
    if ((int64_t)(tx.nLockHeight + MIN_HISTORY) < nBlockHeight){
//	printf("Too far in past!! %ld %ld", tx.nLockHeight + MIN_HISTORY, (uint64_t)nBlockHeight);
        return false;
    }
    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool AreInputsStandard(const CTransaction& tx)
{
    return true;
}

unsigned int GetLegacySigOpCount(const CTransaction& tx)
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
	if(txin.scriptSig.size() == 0)
	    continue;
        nSigOps += txin.scriptSig[0]; //Number of signatures is first byte
    }
    return nSigOps;
}


bool CheckTransaction(const CTransaction& tx, CValidationState &state)
{
    // Basic checks that don't depend on any context
    if (tx.vin.empty())
        return state.DoS(10, error("CheckTransaction() : vin empty"),
                         REJECT_INVALID, "bad-txns-vin-empty");
    if (tx.vout.empty())
        return state.DoS(10, error("CheckTransaction() : vout empty"),
                         REJECT_INVALID, "bad-txns-vout-empty");
    // Size limits
    if (::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CheckTransaction() : size limits failed"),
                         REJECT_INVALID, "bad-txns-oversize");

    // Check for negative or overflow output values
    int64_t nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if (txout.nValue > MAX_MONEY)
            return state.DoS(100, error("CheckTransaction() : txout.nValue too high"),
                             REJECT_INVALID, "bad-txns-vout-toolarge");
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction() : txout total out of range"),
                             REJECT_INVALID, "bad-txns-txouttotal-toolarge");
    }

    int64_t nValueIn = 0;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (txin.nValue > MAX_MONEY)
            return state.DoS(100, error("CheckTransaction() : txin.nValue too high"),
                             REJECT_INVALID, "bad-txns-vin-toolarge");
        nValueIn += txin.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CheckTransaction() : txin total out of range"),
                             REJECT_INVALID, "bad-txns-txintotal-toolarge");
    }

    if(nValueIn < nValueOut){
        return state.DoS(100, error("CheckTransaction() : txin < txout"),
                             REJECT_INVALID, "bad-txns-makes-money");
    }
    //uint64_t nFees = nValueIn - nValueOut;

    //Check message size
    if(tx.msg.size() > MAX_MSG_SIZE){
        return state.DoS(100, error("CheckTransaction() : msg too long"),
                             REJECT_INVALID, "bad-txns-msg-length");
    }

    // Check for duplicate inputs
    set<uint160> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        if (vInOutPoints.count(txin.pubKey))
            return state.DoS(100, error("CheckTransaction() : duplicate inputs"),
                             REJECT_INVALID, "bad-txns-inputs-duplicate");
        vInOutPoints.insert(txin.pubKey);
    }

    // Check for duplicate outputs
    vInOutPoints.clear();
    BOOST_FOREACH(const CTxOut& txout, tx.vout)
    {
        if (vInOutPoints.count(txout.pubKey))
            return state.DoS(100, error("CheckTransaction() : duplicate outputs"),
                             REJECT_INVALID, "bad-txns-output-duplicate");
        vInOutPoints.insert(txout.pubKey);
    }

    if (tx.IsCoinBase())
    {
        if (tx.vin[0].scriptSig.size() != 0){
	    printf("SciptSig: %ld\n", tx.vin[0].scriptSig.size());
            return state.DoS(100, error("CheckTransaction() : coinbase script size"),
                             REJECT_INVALID, "bad-cb-length");
	}
	if(tx.vout.size() != 1){
            return state.DoS(100, error("CheckTransaction() : coinbase outputs"),
                             REJECT_INVALID, "bad-cb-output");
	}
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, tx.vin)
            if (txin.IsNull())
                return state.DoS(10, error("CheckTransaction() : input is null"),
                                 REJECT_INVALID, "bad-txns-input-null");
    }

    return true;
}

int64_t GetMinFee(const CTransaction& tx, unsigned int nBytes, bool fAllowFree, enum GetMinFee_mode mode)
{
    // Base fee is either nMinTxFee or nMinRelayTxFee
    int64_t nBaseFee = (mode == GMF_RELAY) ? tx.nMinRelayTxFee : tx.nMinTxFee;

    int64_t nMinFee = (1 + (int64_t)nBytes / 1000) * nBaseFee;

    if (0)
    {
        // There is a free transaction area in blocks created by most miners,
        // * If we are relaying we allow transactions up to DEFAULT_BLOCK_PRIORITY_SIZE - 1000
        //   to be considered to fall into this category. We don't want to encourage sending
        //   multiple transactions instead of one big transaction to avoid fees.
        // * If we are creating a transaction we allow transactions up to 1,000 bytes
        //   to be considered safe and assume they can likely make it into this section.
        if (nBytes < (mode == GMF_SEND ? 1000 : (DEFAULT_BLOCK_PRIORITY_SIZE - 1000)))
            nMinFee = 0;
    }

    // This code can be removed after enough miners have upgraded to version 0.9.
    // Until then, be safe when sending and require a fee if any output
    // is less than CENT:
    if (!MoneyRange(nMinFee))
        nMinFee = MAX_MONEY;
    return nMinFee;
}

double GetPriority(vector<CTxIn> vtxin){
    double dPriority=0;
    BOOST_FOREACH(CTxIn txin, vtxin)
    {
	int64_t nCredit = txin.nValue;
	dPriority += (double)nCredit * pviewTip->CoinAge(txin.pubKey);
    }
    return dPriority;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransaction &tx, bool fLimitFree,
                        bool* pfMissingInputs, bool fRejectInsaneFee)
{
    //assert(0);

    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return error("AcceptToMemoryPool: : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("AcceptToMemoryPool: : coinbase as individual tx"),
                         REJECT_INVALID, "coinbase");

    // Reject non final tx
    if (!IsFinalTx(tx,chainActive.Height()+5)) //Fudge time to stop height skew problems
        return state.Invalid(error("AcceptToMemoryPool: : transaction not final"),
                         REJECT_INVALID, "final");


    // Check both memory pool and view for this tx    
    uint256 hash = tx.GetTxID();
    CTransaction txout;
    uint256 blockhash;
    //No DoS here because node propagation regularly causes dups
    if (GetTransaction(hash,txout,blockhash))
        return state.Invalid(error("AcceptToMemoryPool: : transaction already exists"),
			REJECT_DUPLICATE, "exists");

    {
        // do all inputs exist?
	vector<CActInfo> balances;
	vector<uint160> keys;
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
	    keys.push_back(txin.pubKey);
        }

	//No DoS here because receiving transaction in different order can cause different
        //memory pool views. This can cause extreme propagation issues but somehow
	//this has been determined to be senders problem
	pviewTip->ConservativeBalances(1,keys,balances);
        for(int i=0; i < (int)tx.vin.size(); i++){
	    uint64_t balance = balances[i].balance;
	    if(balances[i].limit < balance)
		balance = balances[i].limit;
	    if(tx.vin[i].nValue > balance)
		return state.Invalid(error("AcceptToMemoryPool: : insufficient funds"),
			REJECT_DUPLICATE, "bad-txns-inputs-insufficient");
        }

        int64_t nValueIn = tx.GetValueIn();
        int64_t nValueOut = tx.GetValueOut();
        int64_t nFees = nValueIn-nValueOut;

        //Make sure that any created accounts would receive at least fee amount
	balances.clear();
	keys.clear();
        BOOST_FOREACH(const CTxOut txout, tx.vout) {
	    keys.push_back(txout.pubKey);
        }
	pviewTip->ConservativeBalances(1,keys,balances);
        for(int i=0; i < (int)tx.vout.size(); i++){
		if(balances[i].balance == 0 && tx.vout[i].nValue < (uint64_t)nFees){
			return state.Invalid(error("AcceptToMemoryPool: : insufficient funds for creation"),
				REJECT_DUPLICATE, "bad-txns-outputs-insufficient");		
		}
	}

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

  	//allow no output as part of 100% fee tx for pruning
	if(nValueIn == 0){
            return state.DoS(100, error("AcceptToMemoryPool : no inputs/outputs %s",
                                      hash.ToString()),
                             REJECT_INSUFFICIENTFEE, "no i/o");	
	}

	if(nValueOut==0 && !tx.fSetLimit && (tx.vout.size() > 1 || (tx.vout.size() == 1 && tx.vout[0].pubKey != 0))){
            return state.DoS(100, error("AcceptToMemoryPool : destruction transaction not to coinbase %s",
                                      hash.ToString()),
                             REJECT_INSUFFICIENTFEE, "bad destroy");	
	}

	if(nValueIn < nValueOut){
            return state.DoS(100, error("AcceptToMemoryPool : input less than output %s",
                                      hash.ToString()),
                             REJECT_INSUFFICIENTFEE, "neg fee");	
	}

	//TODO: fixme!!!!
        double dPriority = GetPriority(tx.vin);

        CTxMemPoolEntry entry(tx, nFees, GetTime(), dPriority, chainActive.Height());
        unsigned int nSize = entry.GetTxSize();

    	// Size check
    	// Always relay tx's that destroy accounts
    	int64_t txMinFee = GetMinFee(tx, nSize, true, GMF_RELAY);
    	if (nFees < txMinFee && nValueOut != 0)
            return state.DoS(0, error("CheckTransaction() : not enough fees %s, %d < %d",
                                      hash.ToString(), nFees, txMinFee),
                             REJECT_INSUFFICIENTFEE, "insufficient fee");


        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < CTransaction::nMinRelayTxFee)
        {
            static CCriticalSection csFreeLimiter;
            static double dFreeCount;
            static int64_t nLastTime;
            int64_t nNow = GetTime();

            LOCK(csFreeLimiter);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= __ieee754_pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000)
                return state.DoS(0, error("AcceptToMemoryPool : free transaction rejected by rate limiter"),
                                 REJECT_INSUFFICIENTFEE, "insufficient priority");
            LogPrint("mempool", "Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        if (fRejectInsaneFee && nFees > CTransaction::nMinRelayTxFee * 10000)
            return error("AcceptToMemoryPool: : insane fees %s, %d > %d",
                         hash.ToString(),
                         nFees, CTransaction::nMinRelayTxFee * 10000);
        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!CheckInputs(tx, state))
        {
            return error("AcceptToMemoryPool: : CheckInputs failed %s", hash.ToString());
        }

	//Only allow a small number of withdrawal limit update transactions in the pool as these are effectively rate limited
	if(tx.fSetLimit && pool.numLimits(tx.vin[0].pubKey) > (int64_t)(MIN_HISTORY / MIN_LIMIT_TIME)){
            return error("AcceptToMemoryPool: : Too many limit updates %s", hash.ToString());
	}

        // Store transaction in memory
        pool.addUnchecked(hash, entry);
    }

    g_signals.SyncTransaction(hash, tx, NULL);

    return true;
}

CBlockIndex* GetTxBlock(uint256 txid){
    uint256 hashBlock;

    CDiskTxPos postx;
    if(!pblocktree->ReadTxIndex(txid, postx)) 
	return false;

    hashBlock = postx.hashBlock;
    return mapBlockIndex[hashBlock];
}

bool TxExists(uint256 txid){
       CDiskTxPos postx;
       return pblocktree->ReadTxIndex(txid, postx); 
}

int64_t GetDepthInMainChain(uint256 txid){
    LOCK(cs_main);
    {
       CTransaction txOut;
       if (mempool.lookup(txid, txOut))
       {
           return 0;
       }
    }


    CBlockIndex *block = GetTxBlock(txid);
    if(!block)
       return -1;
    return 1+chainActive.Height() - block->nHeight;
}



// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow)
{
    assert(fTxIndex); //No support this function without index
    hashBlock=0;
    LOCK(cs_main);
    {
       if (mempool.lookup(hash, txOut))
       {
           return true;
       }
    }

    if (fTxIndex) {
       //printf("Lookup: %s\n", hash.GetHex().c_str());
       CDiskTxPos postx;
       if (pblocktree->ReadTxIndex(hash, postx)) {
           hashBlock = postx.hashBlock;
	   if(!blockCache.ReadTxFromDisk(txOut,postx))
               return error("%s : Deserialize or I/O error ", __PRETTY_FUNCTION__);
           return true;
       }
       //printf("Could not find\n");
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

void mpz_set_uii(mpz_t &mpz, uint64_t v){
    mpz_import(mpz, 1, -1, sizeof(uint64_t), -1, 0, &v);
}

uint64_t mpz_get_uii(mpz_t &mpz){
    uint64_t v[16];
    mpz_export(v, 0, -1, sizeof(uint64_t), -1, 0, mpz);
    return v[0];
}

int64_t GetBlockValue(uint64_t coinbase, uint64_t nFees)
{
    mpz_t mcb,mquot,t;
    mpz_init(mcb);
    mpz_init(mquot);
    mpz_init(t);
 
    //Setup so half of coinbase distributed in ~10 years
    mpz_set_uii(mcb,coinbase);
    mpz_set_uii(t,243*COIN+10*CENT);
    mpz_mul(mcb,mcb,t);
    mpz_set_uii(t,MAX_MONEY);
    mpz_div(mquot,mcb,t);

    uint64_t value = mpz_get_uii(mquot);

    //cout << __func__ << ": " << coinbase << ", " << nFees << ", " << value << ", " <<  (24310*COIN) << ", " <<  MAX_MONEY << ", " << sizeof(mp_limb_t) << "\n";

    mpz_clear(mcb);
    mpz_clear(mquot);
    mpz_clear(t);

    return value + nFees;
}

static const int64_t nTargetTimespan = 1 * 60 * 60 * 24; // 1 day
static const int64_t nTargetSpacing = 1 * 60; //1 minute
static const int64_t nInterval = nTargetTimespan / nTargetSpacing;

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64_t nTime)
{
    const CBigNum &bnLimit = Params().ProofOfWorkLimit();
    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    if (TestNet() && nTime > nTargetSpacing*2)
        return bnLimit.GetCompact();

    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    while (nTime > 0 && bnResult < bnLimit)
    {
        // Maximum 400% adjustment...
        bnResult *= 4;
        // ... in best-case exactly 4-times-normal target time
        nTime -= nTargetTimespan*4;
    }
    if (bnResult > bnLimit)
        bnResult = bnLimit;
    return bnResult.GetCompact();
}

#define FILTER_LENGTH 1440

double GetNextWorkRequiredI(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    // Genesis block
    if (pindexLast == NULL)
        return 1.0;

    //bool done=false;
    //{
        uint256 hash = pblock->GetHash();
	//Search hash map in case this has already been calculated
        map<uint256,double>::iterator it = mapDifficulty.find(hash);
	if(it != mapDifficulty.end())
		return it->second;

	const CBlockIndex *pprev = pindexLast;
	int count=1;
	while(pprev && pprev->pprev && count <= FILTER_LENGTH){
	    count++;
	    pprev=pprev->pprev;
	}
	uint64_t deltat = pprev->nTime < pblock->nTime ? pblock->nTime - pprev->nTime : 0;
	if(deltat == 0)
	    deltat=1; //Prevent divide by zero
	uint64_t target = nTargetSpacing*count;

	//printf("H: %ld dT %ld, target %ld, %d\n", pblock->nHeight, deltat, target, count);

	double g = pow(target/(double)deltat,1/(double)count);
	
	CBlockHeader lastBlock = pindexLast->GetBlockHeader();
	double f = g * GetNextWorkRequiredI(pindexLast->pprev,&lastBlock);
	if(f < 1.0)
	   f= 1.0;
	mapDifficulty[hash] = f;
	return f;
    //}
}

double GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock){
    double ret = GetNextWorkRequiredI(pindexLast, pblock);
    //printf("Next work required for %ld, %f\n", pblock->nHeight, ret);
#if 0
    if(GetBoolArg("-testnet", false))
	return 1.0;
#endif
    return ret;
}

map<uint256,uint64_t> mapSize;
uint64_t GetSize(const CBlock* pblock){
    uint256 hash = pblock->GetHash();	
    if(mapSize.find(hash) == mapSize.end()){
	mapSize[hash] = ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION);
    }
    return mapSize[hash];
}

uint64_t GetNextMaxSize(const CBlockIndex* pindexLast){
     if(!pindexLast)
	return UINT64_MAX;

     uint64_t accum=0;
     uint64_t cnt=0;
     printf("Getting size for height : %ld\n", pindexLast->nHeight);
     while(pindexLast && (cnt < BLK_SIZE_FILTER)){
    	CBlock block;
    	if (!blockCache.ReadBlockFromDisk(block, pindexLast))
	    break;
	accum += GetSize(&block);
	pindexLast = pindexLast->pprev;
	cnt++;
     }
     if(cnt != BLK_SIZE_FILTER)
	return UINT64_MAX;

     uint64_t v = (accum<<1) / BLK_SIZE_FILTER;
     return v > MAX_BLOCK_SIZE ? v : MAX_BLOCK_SIZE;
}

uint256 GetTargetWork(double nBits){

    CBigNum bnTarget = Params().ProofOfWorkLimit();
    uint256 target = bnTarget.getuint256();

    //printf("Target: %s\n", target.GetHex().c_str());

    assert(nBits>=1.0);
    nBits *= (1LL<<52); //Weird shift
   
    mpz_t mbits,mtarget,t;
    mpz_init(mbits);
    mpz_init(mtarget);
    mpz_init(t);

    mpz_set_d(mbits,nBits);
    mpz_set_uint256(mtarget,target);
    mpz_set_uii(t,(1LL<<52));
    mpz_mul(mtarget,mtarget,t);
    //gmp_printf ("%Zx\n", mtarget);

    
    mpz_div(mtarget,mtarget,mbits);

    //gmp_printf ("%Zx %Zx\n", mtarget, mbits);

    mpz_get_uint256(mtarget,target);
    mpz_clear(mbits);
    mpz_clear(mtarget);
    mpz_clear(t);

    //printf("HashCPOW: %s %f\n", target.GetHex().c_str(), nBits);
    return target;
}

bool CheckProofOfWork(uint256 hash, double nBits)
{
    uint256 target = GetTargetWork(nBits);

    //printf("%s %f\n", hash.GetHex().c_str(), nBits);
    // Check range
#if 0
    if (bnTarget <= 0 || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");
#endif
    // Check proof of work matches claimed amount
    if (hash > target)
        return error("CheckProofOfWork() : hash doesn't match nBits %s %s", hash.GetHex().c_str(), target.GetHex().c_str());

    return true;
}

void SystemResync(bool restart){
    //If caused by GUI, then we need to restart before even trying to run this operation or 
    //it will fail because databases are open and various files etc.
    if(restart){
        std::string strCmd = strCommandLine + " -resync" + " -pid=" + to_string(getpid());
	//boost::replace_all(strCmd, "%s", warning);
        boost::thread t(runCommand, strCmd); // thread runs free
	exit(0);
    }

    if(GetArg("-pid",0LL)){
	int64_t oldPid = GetArg("-pid",0LL);
	//Impossible to check for exit via pid, so use lock

    	boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    	static boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    	while(!lock.try_lock()){
	    MilliSleep(1000);
	}
	lock.unlock();
    }


    remove_all(GetDataDir() / "blocks");
    remove(GetDataDir() / "trie.dat");


    //don't actually need this. can just continue   
    printf("Restarting into normal mode\n");
#if 0
    std::string strCmd = strCommandLine;
    boost::replace_all(strCmd, "-resync", "");
    boost::thread t(runCommand, strCmd); // thread runs free

    exit(0);
#endif
}

bool IsInitialBlockDownload()
{
    if (fImporting || fReindex)
        return true;
//    if (chainActive.Tip() != chainHeaders.Tip() && (chainHeaders.Tip() && chainActive.Tip() != chainHeaders.Tip()->pprev))
//	return true;
    if(setHeightMissing.size() > 5)
	return true;

    static int64_t nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (chainActive.Tip() != pindexLastBest)
    {
        pindexLastBest = chainActive.Tip();
        nLastUpdate = GetTime();
    }
	//printf("Almost online\n");
    return (GetTime() - nLastUpdate < 10 &&
            chainHeaders.Tip()->GetBlockTime() < GetTime() - 24 * 60 * 60 );
}

bool fLargeWorkForkFound = false;
bool fLargeWorkInvalidChainFound = false;
bool fSecretChainAttack = false;

void CheckForkWarningConditions(bool fReorganized = false)
{
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before the last checkpoint)
    if (IsInitialBlockDownload())
        return;

    // We define a condition which we should warn the user about as a fork of at least 72 blocks
    // who's tip is within 720 blocks (+/- 12 hours if no one mines it) of ours
    // We use 72 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 72-block condition and from this always have the most-likely-to-cause-warning fork
    CBlockIndex *pindexBestForkBase = NULL;
    CBlockIndex *pindexBestForkTip = NULL;
    if (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (chainActive.Tip()->GetBlockWork() * 6).getuint256()) {
        pindexBestForkBase = pindexBestInvalid->pprev;
    } else if (fReorganized) {
        // Find a fork up to 72 blocks deep.
        std::set<CBlockIndex*,CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexValid.rbegin();
        while (it != setBlockIndexValid.rend() && (*it)->nHeight + 720 > chainHeaders.Height()) {
            if (!chainHeaders.Contains(*it)) {
                pindexBestForkTip = *it;
                pindexBestForkBase = pindexBestForkTip->pprev;
                break;
            }
            it++;
        }
    }
    while (pindexBestForkBase && !chainHeaders.Contains(pindexBestForkBase))
        pindexBestForkBase = pindexBestForkBase->pprev;
    if (pindexBestForkBase) {
        LogPrintf("CheckForkWarningConditions(): bestForkTip=%s(%i) bestForkBase=%s(%i)\n", pindexBestForkTip->GetBlockHash().ToString().c_str(), pindexBestForkTip->nHeight,
                                                                                         pindexBestForkBase->GetBlockHash().ToString().c_str(), pindexBestForkBase->nHeight);
    }

    if (pindexBestForkTip && pindexBestForkBase) {
        if (pindexBestForkBase == chainHeaders.Tip() || pindexBestForkTip->nChainWork < (pindexBestForkBase->GetBlockWork() * 72).getuint256() + pindexBestForkBase->nChainWork) {
            LogPrintf("CheckForkWarningConditions(): best fork is not dangerous");
            pindexBestForkBase = NULL;
        }
    }

    if (pindexBestForkBase)    {
        if (!fLargeWorkForkFound)
        {
            std::string strCmd = GetArg("-alertnotify", "");
            if (!strCmd.empty())
            {
                std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                                      pindexBestForkBase->phashBlock->ToString() + std::string("'");
                boost::replace_all(strCmd, "%s", warning);
                boost::thread t(runCommand, strCmd); // thread runs free
            }
        }
        if (pindexBestForkTip)
        {
            LogPrintf("CheckForkWarningConditions: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n",
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            fLargeWorkForkFound = true;
        }
        else
        {
            LogPrintf("CheckForkWarningConditions: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n");
            fLargeWorkInvalidChainFound = true;
        }
    }
    else
    {
        fLargeWorkForkFound = false;
        fLargeWorkInvalidChainFound = false;
    }
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
    if (state->nMisbehavior >= GetArg("-banscore", 100))
    {
        LogPrintf("Misbehaving: %s (%d -> %d) BAN THRESHOLD EXCEEDED\n", state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
        state->fShouldBan = true;
    } else
        LogPrintf("Misbehaving: %s (%d -> %d)\n", state->name, state->nMisbehavior-howmuch, state->nMisbehavior);
}

void InvalidBlockFound(CBlockIndex *pindex) {
    // Mark pindex as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
    LogPrintf("Marked %s as invalid\n", pindex->GetBlockHash().ToString().c_str());
    setBlockIndexValid.erase(pindex);

    // Mark its decendants in the main chain (if any) as invalid.
    CBlockIndex *pindexWalk = pindex;
    do {
        CBlockIndex *pindexNext = chainHeaders.Next(pindexWalk);
        if (!pindexNext) break;
        pindexWalk = pindexNext;
        setBlockIndexValid.erase(pindexWalk);
        pindexWalk->nStatus |= BLOCK_FAILED_CHILD;
        LogPrintf("Marked %s as descending from invalid\n", pindexWalk->GetBlockHash().ToString().c_str());
    } while(true);
    // Update pindexBestInvalid if necessary.
    if (pindexBestInvalid==NULL || pindexWalk->nChainWork > pindexBestInvalid->nChainWork) {
        pindexBestInvalid = pindexWalk;
        pblocktree->WriteBestInvalidWork(CBigNum(pindexWalk->nChainWork)); // only for compatibility
        uiInterface.NotifyBlocksChanged();
    }

    // reorganise away from the failed block
    CValidationState stateDummy;
    ActivateBestHeader(stateDummy);
    //ActivateBestChain(stateDummy);
    CheckForkWarningConditions(true);

    LogPrintf("InvalidBlockFound: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n",
      pindex->GetBlockHash().ToString().c_str(), pindex->nHeight,
      log(pindex->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindex->GetBlockTime()).c_str());
    LogPrintf("InvalidChainFound:  current best=%s  height=%d  log2_work=%.8g  date=%s\n",
      chainActive.Tip()->GetBlockHash().ToString().c_str(), chainActive.Height(), log(chainActive.Tip()->nChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()).c_str());
}

uint256 UpdateTime(CBlockHeader& block, const CBlockIndex* pindexPrev)
{
    block.nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    return GetTargetWork(GetNextWorkRequired(pindexPrev, &block));
}

bool CScriptCheck::operator()() const {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, pubKey, *ptxTo, nIn))
        return error("CScriptCheck() : %s VerifySignature failed", ptxTo->GetHash().ToString());
    return true;
}

bool VerifySignature(const uint160 &pubKey, const CTransaction& txTo, unsigned int nIn)
{
    return CScriptCheck(pubKey, txTo, nIn)();
}

bool CheckInputs(const CTransaction& tx, CValidationState &state)
{
    //printf("Check inputs\n");
    if (!tx.IsCoinBase())
    {
	//Don't need to check input balances here because accept to mempool does it using
	//Trie and connectblock also does it with Trie

        for (unsigned int i = 0; i < tx.vin.size(); i++) {
            // Verify signature
            CScriptCheck check(tx.vin[i].pubKey, tx, i);
            if (!check()) {
                return state.DoS(100,false, REJECT_NONSTANDARD, "non-canonical");
            }
        }
    }

    return true;
}



bool DisconnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex)
{
    assert(pindex->GetBlockHash() == chainActive.Tip()->GetBlockHash());

    pindex->fConnected = false;

    //modify txindex
    BOOST_FOREACH(CTransaction tx, block.vtx){
	if(!pblocktree->EraseTxIndex(tx.GetTxID())){
	    LogPrintf("DisconnectBlock: Horrible terrible thing happened\n");
	}
    }

    //About to become an orphan
    //mapOrphanBlocksByPrev.insert(make_pair(block.hashPrevBlock, pindex)); 
    return true;
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("cryptonite-scriptch");
    scriptcheckqueue.Thread();
}

bool ConnectBlock(CBlock& block, CValidationState& state, CBlockIndex* pindex,bool fJustCheck)
{
    //printf("ConnectBlock %d %d\n", fJustCheck, fTxIndex);

    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(block, state, !fJustCheck, !fJustCheck))
        return false;

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == NULL ? uint256(0) : pindex->pprev->GetBlockHash();
    uint256 hashActive = chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : 0;
    //printf("ConnectBlock2 %s %s\n", hashPrevBlock.GetHex().c_str(), chainActive.Tip()->GetBlockHash().GetHex().c_str());

    assert(hashPrevBlock == hashActive);

    // Special case for the genesis block, allows population of coinbase
    bool isGenesis = block.GetHash() == Params().HashGenesisBlock();
    if(isGenesis)
	pindexGenesisBlock = pindex;


    //run checkblock size here now that we can calculate the size. 
#if 1
    CBlockIndex *pindexPrev = mapBlockIndex[block.hashPrevBlock];
    uint64_t max_size = GetNextMaxSize(pindexPrev);

    // Size limits
    if (block.vtx.size() > max_size || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION) > max_size)
        return state.DoS(100, error("AcceptBlock() : size limits failed"),
                         REJECT_INVALID, "bad-blk-length");

#endif

    int64_t nStart = GetTimeMicros();
    int64_t nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(),0,block.GetHash());
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = block.vtx[i];

        nInputs += tx.vin.size();
        nSigOps += GetLegacySigOpCount(tx);

        if (!isGenesis && !tx.IsCoinBase())
        {
            if (!pviewTip->HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock() : inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");

            nFees += tx.GetFee();

	    //ECDSA check on startup takes forever!
            if (!fLoading && !CheckInputs(tx, state)){
                return state.DoS(100, error("ConnectBlock() : inputs nonstandard"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");
	    }

	    if(!fLoading && TxExists(tx.GetTxID())){
                return state.DoS(100, error("ConnectBlock() : tx duplicate"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");
	    }

#if 0   //TODO: this is cool because it does some consistancy checking, but its really slow and maybe won't work once blockchain is incomplete
	    if(fLoading && !TxExists(tx.GetTxID())){
                return error("ConnectBlock() : txindex does not contain transaction! Likely corruption");
	    }
#endif
        }

	pos.nTxOffset=i;
        vPos.push_back(std::make_pair(tx.GetTxID(), pos));
    }
    int64_t nTime = GetTimeMicros() - nStart;
    if (fBenchmark)
        LogPrintf("- Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin)\n", (unsigned)block.vtx.size(), 0.001 * nTime, 0.001 * nTime / block.vtx.size(), nInputs <= 1 ? 0 : 0.001 * nTime / (nInputs-1));

    int64_t nTime2 = GetTimeMicros() - nStart;
    if (fBenchmark)
        LogPrintf("- Verify %u txins: %.2fms (%.3fms/txin)\n", nInputs - 1, 0.001 * nTime2, nInputs <= 1 ? 0 : 0.001 * nTime2 / (nInputs-1));

    if (fJustCheck)
        return true;

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return state.Abort(_("Failed to write transaction index"));

    // Watch for transactions paying to me
    if(!fLoading){
    	for (unsigned int i = 0; i < block.vtx.size(); i++)
            g_signals.SyncTransaction(block.vtx[i].GetTxID(), block.vtx[i], &block);
    }

    // Watch for changes to the previous coinbase transaction.
    static uint256 hashPrevBestCoinBase=0;
    if(!fLoading){
	//g_signals.UpdatedTransaction(hashPrevBestCoinBase);
    }
    hashPrevBestCoinBase = block.GetTxHash(0);

    pindex->fConnected=true;

    return true;
}

// Update the on-disk chain state.
bool static WriteChainState(CValidationState &state) {
    static int64_t nLastWrite = 0;
    if (!IsInitialBlockDownload() || GetTimeMicros() > nLastWrite + 600*1000000) {
        // Typical CCoins structures on disk are around 100 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
//TODO:
 //       if (!CheckDiskSpace(100 * 2 * 2 * pcoinsTip->GetCacheSize()))
 //           return state.Error("out of disk space");
        FlushBlockFile();
        pblocktree->Sync();
//        if (!pviewTip->Flush())
//            return state.Abort(_("Failed to write to coin database"));
        nLastWrite = GetTimeMicros();
    }
    return true;
}

// Update chainActive and related internal data structures.
void static UpdateTip(CBlockIndex *pindexNew) {
    LogPrintf("UpdateTip()\n");

    // Update best block in wallet (so we can detect restored wallets)
    bool fIsInitialDownload = IsInitialBlockDownload();
    if ((chainActive.Height() % 20160) == 0 || (!fIsInitialDownload && (fTrieOnline || ForceNoTrie()) && (chainActive.Height() % 144) == 0))
        g_signals.SetBestChain(chainActive.GetLocator());

    // New best block
    nTimeBestReceived = GetTime();
    mempool.AddTransactionsUpdated(1);

    chainActive.SetTip(pindexNew);    
    LogPrintf("UpdateTip: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f\n",
      chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(), log(chainActive.Tip()->nChainWork.getdouble())/log(2.0), (unsigned long)chainActive.Tip()->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
      Checkpoints::GuessVerificationProgress(chainActive.Tip()));

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload && (fTrieOnline || ForceNoTrie()))
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = chainActive.Tip();
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->nVersion > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            LogPrintf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, (int)CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }
    cvBlockChange.notify_all();
}

// Disconnect chainActive's tip.
bool static DisconnectTip(CValidationState &state) {
    LogPrintf("Disconnect tip : %s\n", chainActive.Tip()->GetBlockHash().GetHex());
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    CBlock block;
    if (!blockCache.ReadBlockFromDisk(block, pindexDelete)){
        printf("Failed to read block1\n");
	assert(0);
	return state.Abort(_("Failed to read block1"));
    }
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        if (!DisconnectBlock(block, state, pindexDelete))
            return error("DisconnectTip() : DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
    }
    if (fBenchmark)
        LogPrintf("- Disconnect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!WriteChainState(state))
        return false;
    // Resurrect mempool transactions from the disconnected block.
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
        // ignore validation errors in resurrected transactions
        list<CTransaction> removed;
        CValidationState stateDummy; 
        if (!tx.IsCoinBase())
            AcceptToMemoryPool(mempool, stateDummy, tx, false, NULL);
    }
    // Update chainActive and related variables.
    UpdateTip(pindexDelete->pprev);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
        SyncWithWallets(tx.GetTxID(), tx, NULL);
    }
    mapBlockByHeight.erase(block.nHeight);
    return true;
}

// Connect a new block to chainActive.
bool static ConnectTip(CValidationState &state, CBlockIndex *pindexNew) {
    AssertLockHeld(cs_main);

    assert(pindexNew->pprev == chainActive.Tip());

    LogPrintf("Connect tip : %s\n", pindexNew->GetBlockHash().GetHex());

    // Read block from disk.
    CBlock block;
    if (!blockCache.ReadBlockFromDisk(block, pindexNew))
        return state.Abort(_("Failed to read block2"));
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CInv inv(MSG_BLOCK, pindexNew->GetBlockHash());
        if (!ConnectBlock(block, state, pindexNew)) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew);
            return error("ConnectTip() : ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        mapBlockSource.erase(inv.hash);
    }
    if (fBenchmark)
        LogPrintf("- Connect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);
    // Write the chain state to disk, if necessary.
    if (!WriteChainState(state))
        return false;
    // Remove conflicting transactions from the mempool.
    BOOST_FOREACH(const CTransaction &tx, block.vtx) {
        mempool.remove(tx);
    }
    // Update chainActive & related variables.
    UpdateTip(pindexNew);

    // ... and about transactions that got confirmed: 
    if(!fLoading){
    	BOOST_FOREACH(const CTransaction &tx, block.vtx) {
            SyncWithWallets(tx.GetTxID(), tx, &block);
    	}
    }

    if(fLoading || fValidating){
	uint64_t lowest = chainHeaders.Height() > (int64_t)MIN_HISTORY ? chainHeaders.Height() - MIN_HISTORY : chainHeaders.Height();
	uint64_t total = chainHeaders.Height() > (int64_t)MIN_HISTORY ? MIN_HISTORY : chainHeaders.Height();
	
 	ShowProgress(_("Rescanning..."), (int)(100.0 * (chainActive.Height() - lowest) / (double)total));
    }

    //Update the sync point to enable faster startup and trimming
    if(pindexSyncPoint && (pindexSyncPoint->nHeight + (int64_t)MIN_HISTORY) < pindexNew->nHeight && pindexNew->nHeight > (int64_t)MIN_HISTORY){
	//write crap into blockdb
	pindexSyncPoint=chainActive[pindexNew->nHeight-MIN_HISTORY];
	pblocktree->WriteSyncPoint(pindexSyncPoint->GetBlockHash());
	pblocktree->Flush();
    }

    mapBlockByHeight[pindexNew->nHeight] = pindexNew;
    return true;
}

// Try to make some progress towards making pindexMostWork the active block.
static bool ActivateBestChainStep(CValidationState &state) {
    AssertLockHeld(cs_main);
    //printf("Activate best chain step\n");

    if (!ActivateBestHeader(state))
        return false;

    if (chainHeaders.Tip() == NULL)
        return true;

    //First unwind the active chain
    CBlockIndex *pindexFork = chainHeaders.FindFork(chainActive.Tip());
    while(chainActive.Tip() != pindexFork){
  	DisconnectTip(state);
    }


    int nHeight = chainActive.Height()+1;
    //printf("nHeight %d\n", nHeight);
    bool fError=false;

    while (nHeight <= (int)chainHeaders.Height()) {
        CBlockIndex *pindexNew = chainHeaders[nHeight];
	//printf("pindexNew %p\n", pindexNew);
        if (!(pindexNew->nStatus & BLOCK_HAVE_DATA) ||
            (pindexNew->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS){
	    LogPrintf("Cannot fastforward chain because of missing data: %s\n", pindexNew->GetBlockHash().GetHex().c_str());
	    printf("Cannot fastforward chain because of missing data: %s %d\n", pindexNew->GetBlockHash().GetHex().c_str(), pindexNew->nStatus);
	    UpdateMissingHeight();
            break;
	}
        pindexNew->nChainTx = (pindexNew->pprev ? pindexNew->pprev->nChainTx : 0) + pindexNew->nTx;
        if (!ConnectTip(state, pindexNew)){
	    LogPrintf("Cannot fastforward chain because of connecttip fail: %s\n", pindexNew->GetBlockHash().GetHex().c_str());
	    printf("Cannot fastforward chain because of connecttip fail: %s\n", pindexNew->GetBlockHash().GetHex().c_str());
	    UpdateMissingHeight();
            fError=true;
	    break;
	}
        UpdateMissingHeight();
	nHeight++;
    }

    uint256 badBlock;
    if(!pviewTip->Activate(chainActive.Tip(),badBlock)){
	LogPrintf("Activate failed\n");
	state.DoS(100, error("ActivateBestChain() : inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");
	printf("Hash: %s\n", badBlock.GetHex().c_str());
	InvalidBlockFound(mapBlockIndex[badBlock]);
	return ActivateBestChain(state); //Loop until the pain stops
    }
    pviewTip->Flush();

    vector<CTransaction> conflicts;
    mempool.validate(conflicts);

    // Tell wallet about transactions that went from mempool
    // to conflicted:
    if(!fLoading){
    	BOOST_FOREACH(const CTransaction &tx, conflicts) {
            SyncWithWallets(tx.GetTxID(), tx, NULL);
    	}
    }

    if (!pblocktree->Flush())
        return state.Abort(_("Failed to sync block index"));
    return !fError;
}

// Requires cs_main
CCriticalSection cs_missing;
void static UpdateMissingHeight() {
    AssertLockHeld(cs_main);
    LOCK(cs_missing);

    int nWorstHeight = chainHeaders.Height() - MIN_HISTORY;

    if(fTrieOnline && !ForceNoTrie()){
    	CBlockIndex *pfork = chainActive.FindFork(chainHeaders.Tip());
	nWorstHeight = pfork->nHeight;
    }

    if(nWorstHeight < 1) //Never request genesis
	nWorstHeight=1; 
    int nBestHeaderHeight = chainHeaders.Height();
   

    //TODO: this is just used for sync
    int nBestHeight=nWorstHeight;
    for(;nBestHeight<nBestHeaderHeight;nBestHeight++){
	if(mapBlockByHeight.count(nBestHeight)==0)
	    break;
    }

    //printf("Update: %d %d %d %d %ld\n", nHeight, nBestHeight, nWorstHeight, nBestHeaderHeight, mapBlockByHeight.count(nHeight));

    setHeightMissing.clear();
    int nHeight = nWorstHeight;
    for(;nHeight < nBestHeight + MAX_BLOCKS_IN_TRANSIT && nHeight <= nBestHeaderHeight; nHeight++){
	    CBlockIndex *pindex = chainHeaders[nHeight];
	    if(!(pindex->nStatus & BLOCK_HAVE_DATA) || (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS ){
            	setHeightMissing.insert(nHeight);
		//printf("Missing %d\n", nHeight);
	    }
    }
}

int GetTotalMissing(){
    LOCK(cs_missing);
    int nWorstHeight = fTrieOnline ? chainActive.Height() : chainHeaders.Height() - MIN_HISTORY;
    if(nWorstHeight<1)
	nWorstHeight=1;
    int nBestHeaderHeight = chainHeaders.Height();
    int missing=0;
//    int nBestHeight=nWorstHeight;
    for(int i=nWorstHeight;i<nBestHeaderHeight;i++){
	if(mapBlockByHeight.count(i)==0)
	    missing++;
    }
    return missing;
}

bool ActivateBestHeader(CValidationState &state) {
    CBlockIndex *pindexNewBest = NULL;

    //	 In case the current best is invalid, do not consider it.
    {
	LOCK(cs_main);
    	while (chainHeaders.Tip() && chainHeaders.Tip()->nStatus & BLOCK_FAILED_MASK)
            chainHeaders.SetTip(chainHeaders.Tip()->pprev);
    }
    do {
        // Find best candidate header.
         {
            std::set<CBlockIndex*,CBlockIndexWorkComparator>::iterator it = setBlockIndexValid.end();
            if (it == setBlockIndexValid.begin()) {
		 printf("no set\n");
                 return true;
            }
            it--;
            pindexNewBest = *it;
            if ((pindexNewBest->nStatus & BLOCK_FAILED_MASK) || (pindexNewBest->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) {
                // Entry isn't a valid candidate; drop it, and find another.
                setBlockIndexValid.erase(it);
                continue;
            }
         }
 
        // Check whether it's actually an improvement.
        if (chainHeaders.Tip() && CBlockIndexWorkComparator()(chainHeaders.Tip(),pindexNewBest)) {
	    //printf("no improve %s %s\n", pindexNewBest->nChainWork.GetHex().c_str());
            break;
        }
 
        // Check tree nodes between the candidate new best and the currently-accepted best.
        CBlockIndex *pindexTest = pindexNewBest;
        while (pindexTest && !chainHeaders.Contains(pindexTest)) {
            if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
                // Invalid node found, remove the entire chain after it from the set of candidates.
                if (pindexBestInvalid == NULL || pindexTest->nChainWork > pindexBestInvalid->nChainWork)
                    pindexBestInvalid = pindexTest;
                CBlockIndex *pindexFailed = pindexNewBest;
                while (pindexTest != pindexFailed) {
                    pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    setBlockIndexValid.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (pindexTest && pindexTest->nStatus & BLOCK_FAILED_MASK)
            continue;
	//printf("active loop done\n");
        break;
    } while(true);

    // We have a new best header.
    CBlockIndex *pindexFork = pindexNewBest;
    bool fDisconnectedAny = false;
    
    //printf("pindexFork: %p\n", pindexFork);

    while(chainHeaders.FindFork(pindexFork) != chainHeaders.Tip()){
            // We need to disconnect a block, as it's no longer in the best chain.
	    while(!chainHeaders.Contains(chainActive.Tip())){
		LOCK(cs_main);
            	if (!DisconnectTip(state))
                    return error("Disconnecting tip %i (%s) failed", chainActive.Height(), chainActive.Tip()->GetBlockHash().ToString().c_str());
	    }

	    {
		LOCK(cs_main);
	    	chainHeaders.SetTip(chainHeaders.Tip()->pprev);
	    }
            fDisconnectedAny = true;
    }
   
    {
	LOCK(cs_main);
    	chainHeaders.SetTip(pindexFork);
    }
    UpdateMissingHeight();

    if (fDisconnectedAny)
        CheckForkWarningConditions(true);

    //printf("New best header %ld\n", chainHeaders.Height());
    return true;
}

bool ActivateBestChain(CValidationState &state) {
    CBlockIndex *pindexNewTip = NULL;

    //printf("Activate best chain!\n");

    bool fInitialDownload;
    {
        LOCK(cs_main);

        if (!ActivateBestChainStep(state))
    	    return false;

        pindexNewTip = chainActive.Tip();
        fInitialDownload = IsInitialBlockDownload();
    }

    // When we reach this point, we switched to a new tip (stored in pindexNewTip).
    // Notifications/callbacks that can run without cs_main
    //printf("Initial download %d\n", fInitialDownload);
    if (!fLoading && (fTrieOnline || ForceNoTrie())) {
        uint256 hashNewTip = pindexNewTip->GetBlockHash();

        // Relay inventory, but don't relay old inventory during initial block download.
        int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
             pnode->PushInventory(CInv(MSG_BLOCK, hashNewTip));

        std::string strCmd = GetArg("-blocknotify", "");
        if (!strCmd.empty()) {
            boost::replace_all(strCmd, "%s", hashNewTip.GetHex());
            boost::thread t(runCommand, strCmd); // thread runs free
        }
     }

    //printf("%ld %ld\n", chainActive.Height(), chainHeaders.Height());
    return true;
}

bool ActivateTrie(CValidationState &state){
    bool ret = ActivateBestChain(state);
    // New best?
    LogPrintf("Tip: %s\n", chainActive.Tip()->GetBlockHeader().GetHash().GetHex().c_str());
    return ret;
}

set<NodeId> AllNodes(){
    set<NodeId> ret;
    LOCK(cs_vNodes);
    BOOST_FOREACH(CNode* pnode, vNodes){
	ret.insert(pnode->id);
    }
    return ret;
}


bool FindBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    bool fUpdatedLast = false;

    LOCK(cs_LastBlockFile);

    if (fKnown) {
        if (nLastBlockFile != pos.nFile) {
            nLastBlockFile = pos.nFile;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
            fUpdatedLast = true;
        }
    } else {
        while (infoLastBlockFile.nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, infoLastBlockFile.ToString());
            FlushBlockFile(true);
            nLastBlockFile++;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile); // check whether data for the new file somehow already exist; can fail just fine
            fUpdatedLast = true;
        }
        pos.nFile = nLastBlockFile;
        pos.nPos = infoLastBlockFile.nSize;
    }

    infoLastBlockFile.nSize += nAddSize;
    infoLastBlockFile.AddBlock(nHeight, nTime);

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (infoLastBlockFile.nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error("out of disk space");
        }
    }

    if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        return state.Abort(_("Failed to write file info"));
    if (fUpdatedLast)
        pblocktree->WriteLastBlockFile(nLastBlockFile);

    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    if (nFile == nLastBlockFile) {
        pos.nPos = infoLastBlockFile.nUndoSize;
        nNewSize = (infoLastBlockFile.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
            return state.Abort(_("Failed to write block info"));
    } else {
        CBlockFileInfo info;
        if (!pblocktree->ReadBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to read block info"));
        pos.nPos = info.nUndoSize;
        nNewSize = (info.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to write block info"));
    }

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

bool CheckBlockHeader(const CBlockHeader &header, CValidationState &state, bool fCheckPOW)
{
    // Can only check that the block conforms to minimum proof of work until we are able to attach it
    if (fCheckPOW && !CheckProofOfWork(header.GetHash(), 1.0)){
	printf("Failed check\n");
        return state.DoS(50, error("CheckBlockHeader() : proof of work failed"),
                         REJECT_INVALID, "high-hash");
    }

    // Check timestamp
    if (header.GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(error("CheckBlockHeader() : block timestamp too far in the future"));

    return true;
}


bool CheckBlock(const CBlock& block, CValidationState& state, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.
    if (!CheckBlockHeader(block, state, fCheckPOW))
        return false;

    // Size limits
    if (block.vtx.empty())
        return state.DoS(100, error("CheckBlock() : size limits failed"),
                         REJECT_INVALID, "bad-blk-length");

    // First transaction must be coinbase, the rest must not be, genesis TX is non-standard
    if ((block.vtx.empty() || !block.vtx[0].IsCoinBase()) && block.nHeight != 0)
        return state.DoS(100, error("CheckBlock() : first tx is not coinbase"),
                         REJECT_INVALID, "bad-cb-missing");

    // Coinbase lockheight must be = height
    if (block.vtx[0].nLockHeight != block.nHeight){
	return state.DoS(100, error("CheckBlock() : coinbase lockheight != block height"),
			REJECT_INVALID, "bad-cb-height");
    }

    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i].IsCoinBase())
            return state.DoS(100, error("CheckBlock() : more than one coinbase"),
                             REJECT_INVALID, "bad-cb-multiple");

    // Check transactions
    if(block.nHeight!=0){
    	BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!CheckTransaction(tx, state))
            	return error("CheckBlock() : CheckTransaction failed");
    }

    //Check for multiple limit updates or withdrawal + limit update combo
    set<uint160> setLimit, setWD;
    BOOST_FOREACH(const CTransaction& tx, block.vtx){
	if(tx.fSetLimit){
	    if(setLimit.count(tx.vin[0].pubKey) || setWD.count(tx.vin[0].pubKey)){
		return error("CheckBlock() : Limit and withdrawal overlap");
	    }
	    setLimit.insert(tx.vin[0].pubKey);
	}else{
	    BOOST_FOREACH(const CTxIn txin, tx.vin){
		if(setLimit.count(txin.pubKey)){
		    return error("CheckBlock() : Limit and withdrawal overlap");
		}
		setWD.insert(txin.pubKey);
	    }
	}
    }

    // Build the merkle tree already. We need it anyway later, and it makes the
    // block cache the transaction hashes, which means they don't need to be
    // recalculated many times during this block's validation.
    block.BuildMerkleTree();

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    for (unsigned int i = 0; i < block.vtx.size(); i++) {
        uniqueTx.insert(block.vtx[i].GetTxID());
    }
    if (uniqueTx.size() != block.vtx.size())
        return state.DoS(100, error("CheckBlock() : duplicate transaction"),
                         REJECT_INVALID, "bad-txns-duplicate", true);

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, block.vtx)
    {
        nSigOps += GetLegacySigOpCount(tx);
    }

    // Check merkle root
    if (fCheckMerkleRoot && block.hashMerkleRoot != block.vMerkleTree.back())
        return state.DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"),
                         REJECT_INVALID, "bad-txnmrklroot", true);

    return true;
}

bool static WriteBlockPosition(CBlockIndex *pindexNew, const CBlock &block, const CDiskBlockPos& pos)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus = (pindexNew->nStatus & ~BLOCK_HAVE_MASK) | BLOCK_HAVE_DATA;
    if ((pindexNew->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS)
        pindexNew->nStatus = (pindexNew->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TRANSACTIONS;
 
    return pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexNew));
 }


bool static AcceptBlockHeader(const CBlockHeader &block, CValidationState& state, CBlockIndex* &pindexNew)
{
    printf("Accept block header\n");

    // Check for duplicate
    uint256 hash = block.GetHash();
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        pindexNew = mi->second;
    if (pindexNew && ((pindexNew->nStatus & BLOCK_FAILED_MASK) != 0 || (pindexNew->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE))
        return true;

    // Get prev block index
    CBlockIndex* pindexPrev = NULL;

    int nHeight = 0;
    if (hash != Params().HashGenesisBlock()) {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("AcceptBlockHeader() : prev block not found"), 0, "bad-prevblk");
        pindexPrev = (*mi).second;

        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("AcceptBlockHeader() : extended invalid chain"));

        //if (!pindexPrev->fConnected)
        //    return state.Invalid(error("AcceptBlockHeader() : %s extending orphan block %s", hash.ToString().c_str(), pindexPrev->ToString().c_str()));


        nHeight = pindexPrev->nHeight+1;

	// Check headers nHeight
        {
	    if(nHeight!=(int)block.nHeight)
		return state.Invalid(error("AcceptBlockHeader() : block's nHeight not correct"),
				    REJECT_INVALID, "bad-nheight");

        }

        // Check proof of work
	{
		//run real checkprooffowork here after we find out number of bits
	        if (!CheckProofOfWork(block.GetHash(),GetNextWorkRequired(pindexPrev, &block)))
	            return state.DoS(100, error("AcceptBlockHeader() : incorrect proof of work"),
	                             REJECT_INVALID, "bad-diffbits");
	}

        // Check timestamp against prev
        if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
            return state.Invalid(error("AcceptBlockHeader() : block's timestamp is too early"),
                                 REJECT_INVALID, "time-too-old");

        // Do not allow headers before a checkpoint we have reached already.
        if (nHeight <= Checkpoints::GetLastCheckpointHeight(chainHeaders.Height()))
            return state.DoS(100, error("AcceptBlockHeader() : rewriting pre-checkpoint chain"));

	//this is a pretty bad condition. Someone may be attacking the chain or the user
	//may currently be the victim of such a thing. This error should be noticed especially
	//since deflecting the block will cause future related errors to go unreported
	if (pindexSyncPoint && nHeight <= pindexSyncPoint->nHeight){
	    LogPrintf("AcceptBlockHeader() : unreachable blocks are being mined, possible secret chain attack\n");
	    fSecretChainAttack=true;

            std::string strCmd = GetArg("-alertnotify", "");
            if (!strCmd.empty())
            {
                std::string warning = std::string("'Warning: unreachable blocks are being mined, possible secret chain attack'");
                boost::replace_all(strCmd, "%s", warning);
                boost::thread t(runCommand, strCmd); // thread runs free
            }

            return state.DoS(100, error("AcceptBlockHeader() : rewriting pre-syncpoint chain"));
	}

        // Check that the block chain matches the known block chain up to a checkpoint
        if (!Checkpoints::CheckBlock(nHeight, hash))
            return state.DoS(100, error("AcceptBlockHeader() : rejected by checkpoint lock-in at %d", nHeight),
                             REJECT_CHECKPOINT, "checkpoint mismatch");

        // Don't accept any forks from the main chain prior to last checkpoint
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("AcceptBlockHeader() : forked chain older than last checkpoint (height %d)", nHeight));
    }

    // Construct new block index object
    if (pindexNew==NULL)
        pindexNew = InsertBlockIndex(hash, block);

    if ((pindexNew->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE)
        pindexNew->nStatus = (pindexNew->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TREE;
    if (LinkOrphans(&block.hashPrevBlock))
        if (!ActivateBestHeader(state))
            return false;
    if (!pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexNew)))
        return state.Abort(_("Failed to write block index"));
    pindexNew->fConnected=true;
   // printf("Accepted block header\n");
   UpdateMissingHeight();

    return true;
}

// Precondition: block passes CheckBlock()
bool static AcceptBlock(CBlock& block, CValidationState& state)
{
    //LogPrintf("AcceptBlock()\n");
    CBlockIndex *pindexNew = NULL;
    if (!AcceptBlockHeader(block, state, pindexNew))
        return false;

    if (pindexNew->nStatus & BLOCK_HAVE_DATA && (pindexNew->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS){
	//printf("Hrm\n");
   	if(mapBlockByHeight.count(pindexNew->nHeight)==0)
    	    mapBlockByHeight[pindexNew->nHeight] = pindexNew;
	UpdateMissingHeight();
        return true;
    }

    int nHeight = pindexNew->nHeight;
    // Check that all transactions are finalized
    BOOST_FOREACH(const CTransaction& tx, block.vtx){
        if (!IsFinalTx(tx, nHeight, block.GetBlockTime()))        
            return state.DoS(10, error("AcceptBlock() : contains a non-final transaction"));
    }

    try {
        unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (!FindBlockPos(state, blockPos, nBlockSize+8, nHeight, block.nTime, false))
            return error("AcceptBlock() : FindBlockPos failed");
        if (!blockCache.WriteBlockToDisk(block, blockPos))
            return state.Abort(_("Failed to write block"));
        if (!WriteBlockPosition(pindexNew, block, blockPos))
            return state.Abort(_("Failed to write block position to index"));
        if (!ActivateBestChain(state))
            return false;
    } catch(std::runtime_error &e) {
        return state.Abort(_("System error: ") + e.what());
    }
 
    if (!pblocktree->Flush())
        return state.Abort(_("Failed to sync block index"));

    //Only update if empty, meaning this is an unconnected block
    if(mapBlockByHeight.count(nHeight)==0)
    	mapBlockByHeight[nHeight] = pindexNew;
    UpdateMissingHeight();
 
    printf("Accepted block %ld\n", pindexNew->nHeight);
    return true;
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

int64_t CBlockIndex::GetMedianTime() const
{
    const CBlockIndex* pindex = this;
    for (int i = 0; i < nMedianTimeSpan/2; i++)
    {
        if (!chainActive.Next(pindex))
            return GetBlockTime();
        pindex = chainActive.Next(pindex);
    }
    return pindex->GetMedianTimePast();
}

bool ProcessBlockHeader(CValidationState &state, const CBlockHeader* pheader){
    uint256 hash = pheader->GetHash();
    if (mapBlockIndex.count(hash))
        return true;

    // Preliminary checks
    if (!CheckBlockHeader(*pheader, state)){
	LogPrintf("CheckBlockHeader(): %s\n", state.GetRejectReason());
        return error("ProcessBlockHeader() : CheckBlockHeader FAILED");
    } 

    // Include in the block tree.
    CBlockIndex *pindexNew = NULL;
    if (!AcceptBlockHeader(*pheader, state, pindexNew))
        return error("ProcessBlockHeader() : AcceptBlockHeader FAILED");

    if(fTrieOnline && chainHeaders.Height() > (chainActive.Height() + (int64_t)MIN_HISTORY) && !ForceNoTrie()){
	fNeedsResync = true;
	LogPrintf("Warning: saved state too old. Fast forward sync may not be possible. Run Resync!!!\n");
	strMiscWarning = std::string("Warning: saved state too old. Fast forward sync may not be possible. Run Resync!!!");
    }else{
	fNeedsResync = false;
	if(strMiscWarning == std::string("Warning: saved state too old. Fast forward sync may not be possible. Run Resync!!!"))
	    strMiscWarning = "";
    }

    return true;
}

void PushGetBlocks(CNode* pnode, CBlockIndex* pindexBegin, uint256 hashEnd)
{
#if 0
    // Filter out duplicate requests
    if (pindexBegin == pnode->pindexLastGetBlocksBegin && hashEnd == pnode->hashLastGetBlocksEnd)
        return;
    pnode->pindexLastGetBlocksBegin = pindexBegin;
    pnode->hashLastGetBlocksEnd = hashEnd;
#endif
    pnode->PushMessage("getblocks", chainActive.GetLocator(pindexBegin), hashEnd);
}

bool ProcessBlock(CValidationState &state, CBlock* pblock, CNode* pfrom)
{
    LOCK(cs_main);
    // Preliminary checks
    // in case the transactions and merkle root match, but CheckBlock still fails, we can mark the block as permanently invalid.
    if (!CheckBlock(*pblock, state))
        return error("ProcessBlock() : CheckBlock FAILED");

    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (pblock->hashPrevBlock != 0 && !mapBlockIndex.count(pblock->hashPrevBlock))
    {
        LogPrintf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().c_str());
	if(mapUnindexed.count(pblock->GetHash())){
	    LogPrintf("ProcessBlock: Orphan already exists! %s\n", pblock->GetHash().GetHex());
	    return true;
	}

        // Accept orphans as long as there is a node to request its parents from
        if (pfrom){
            CBlock* pblock2 = new CBlock(*pblock);
            mapUnindexedByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2->GetHash()));
            mapUnindexed.insert(make_pair(pblock2->GetHash(), pblock2));

 	    if(!mapUnindexed.count(pblock->hashPrevBlock)) {
            	// Ask this guy to fill in what we're missing
            	PushGetBlocks(pfrom, chainActive.Tip(), pblock->hashPrevBlock);
	    }
        }
        return true;
    }
  
    // Process the header, store the block to disk, and connect it if necessary.
    bool fSuccess = AcceptBlock(*pblock, state);

    //It may be possible to bring some orphans online now
    bool progress=true;
    while(progress){	
	progress=false;
    	for(multimap<uint256,uint256>::iterator it=mapUnindexedByPrev.begin(); it!= mapUnindexedByPrev.end(); it++){
	    uint256 parent = it->first;
	    if(mapBlockIndex.count(parent)){
		AcceptBlock(*mapUnindexed[it->second], state);
		delete mapUnindexed[it->second];
		mapUnindexed.erase(it->second);
		mapUnindexedByPrev.erase(it);
		progress=true;
		break;
	    }
	}
    }

    UpdateMissingHeight();
 
    if (!fSuccess)
        return error("ProcessBlock() : AcceptBlock FAILED");
 
    LogPrintf("ProcessBlock: ACCEPTED %d\n", pblock->nHeight);

    return true;
}

//Called to try and bring trie online
void ActivateTrie(){
    if(!trieSync.ReadyToBuild())
	return;
 
    LOCK(cs_main); //Don't need anything happening while we embark on most dangerous activity ever invented
    printf("Ready to go online\n");

    uint256 block;
    TrieNode* root = trieSync.Build(block);
    uint256 hash = root->Hash();

    CBlockIndex *pindex = mapBlockIndex[block];
    if(pindex->hashAccountRoot != hash){
	printf("WTF, account hash no match!!!\n");
	strMiscWarning = "Warning: The download trie/blockchain appears to have invalid data. May need to try again";
	//not clear what we can mark as bad here, this should be impossible
	//unless 1 of the blocks used to download was forgery, very bad situation
	//probably warn user and restart triesync is best we can do	
	return;
    }
    printf("Account trie successfully constructed at %ld\n", pindex->nHeight);
    //Try to locate any blocks in chainHeaders that don't validate. If trie ends up too young we will have
    //to abort
    chainActive.SetTip(pindex);
    pviewTip->Force(root,block);
    
    CValidationState state;
    fValidating=true; //Force emission of progress updates for GUI
    ActivateBestChain(state);
    fValidating=false;
    //At this point chainActive will be >= block and <= chainHeaders, we need to check to make sure the amount of
    //of work is withing guidelines. 
    if(chainActive.Height() >= pindex->nHeight + (int64_t)MIN_HISTORY){
	//Good
	printf("Ready for committal\n");
	fTrieOnline=true;
	//write crap into blockdb
	pblocktree->WriteSyncPoint(block);
	pblocktree->Flush();
	pindexSyncPoint=pindex;
    }else{
	//Very bad
	trieSync.Reset();
    }
}


CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        uint256 hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i], hash))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}








uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid) {
    if (height == 0) {
        // hash at height 0 is the txids themself
        return vTxid[pos];
    } else {
        // calculate left hash
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        // calculate right hash if not beyong the end of the array - copy left hash otherwise1
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        // combine subhashes
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) {
    // determine whether this node is the parent of at least one matched txid
    bool fParentOfMatch = false;
    for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
        fParentOfMatch |= vMatch[p];
    // store as flag bit
    vBits.push_back(fParentOfMatch);
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, store hash and stop
        vHash.push_back(CalcHash(height, pos, vTxid));
    } else {
        // otherwise, don't store any hash, but descend into the subtrees
        TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
        if (pos*2+1 < CalcTreeWidth(height-1))
            TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch) {
    if (nBitsUsed >= vBits.size()) {
        // overflowed the bits array - failure
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, use stored hash and do not descend
        if (nHashUsed >= vHash.size()) {
            // overflowed the hash array - failure
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch) // in case of height 0, we have a matched txid
            vMatch.push_back(hash);
        return hash;
    } else {
        // otherwise, descend into the subtrees to extract matched txids and hashes
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
        else
            right = left;
        // and combine them before returning
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch) {
    vMatch.clear();
    // An empty set will not work
    if (nTransactions == 0)
        return 0;
    // there can never be more hashes provided than one for every txid
    if (vHash.size() > nTransactions)
        return 0;
    // there must be at least one bit per node in the partial tree, and at least one node per hash
    if (vBits.size() < vHash.size())
        return 0;
    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;
    // traverse the partial tree
    unsigned int nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
    // verify that no problems occured during the tree traversal
    if (fBad)
        return 0;
    // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
    if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
        return 0;
    // verify that all hashes were consumed
    if (nHashUsed != vHash.size())
        return 0;
    return hashMerkleRoot;
}







bool AbortNode(const std::string &strMessage) {
    strMiscWarning = strMessage;
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode(_("Error: Disk space is low!"));

    return true;
}

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

bool static LinkOrphans(const uint256 *phashParent) {
    bool fWorkDone = false;
    const uint256 &hashGenesisBlock = Params().HashGenesisBlock();

    deque<multimap<uint256, CBlockIndex*>::iterator> vTodo;
    if (phashParent) {
        map<uint256, CBlockIndex*>::iterator itpar = mapBlockIndex.find(*phashParent);
        if (*phashParent == uint256(0) || (itpar != mapBlockIndex.end() && itpar->second->nHeight != -1)) {
            multimap<uint256, CBlockIndex*>::iterator it = mapOrphanBlocksByPrev.find(*phashParent);
            while (it != mapOrphanBlocksByPrev.end() && it->first == *phashParent) { //How would it->first ever not be phashParent?
                vTodo.push_back(it);
                it++;
            }
        }
    } else {
        // First find unconnected blocks whose parent is connected.
        for (multimap<uint256, CBlockIndex*>::iterator it = mapOrphanBlocksByPrev.begin(); it != mapOrphanBlocksByPrev.end(); ) {
            multimap<uint256, CBlockIndex*>::iterator itnow = it++;

            if (itnow->second->fConnected) {
                mapOrphanBlocksByPrev.erase(itnow);
                continue;
            }
            map<uint256, CBlockIndex*>::iterator itprev = mapBlockIndex.find(itnow->first);
            if (itnow->first == uint256(0) || (itprev != mapBlockIndex.end() && itprev->second->fConnected)) {
                vTodo.push_back(itnow);
            }
        }
    }

    // Iterate as long as such parent-connected unconnecteds exist, adding children to the
    // queue after adding a node.
    while (!vTodo.empty()) {
        multimap<uint256, CBlockIndex*>::iterator it = vTodo.front();
        uint256 hashPrev = it->first;
        CBlockIndex *pindex = it->second;
        mapOrphanBlocksByPrev.erase(it);
        vTodo.pop_front();
	//printf("vtodo\n");
        if (hashPrev == uint256(0)) {
            if (pindex->GetBlockHash() != hashGenesisBlock) {
                continue;
            }
            // Deal with the genesis block specially.
            pindexGenesisBlock = pindex;
            pindex->fConnected=true;
            pindex->nChainWork = pindex->GetBlockWork().getuint256();
            pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_TRANSACTIONS;
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
        } else {
            pindex->pprev = mapBlockIndex[hashPrev];
            pindex->nChainWork = pindex->pprev->nChainWork + pindex->GetBlockWork().getuint256();
            if (pindex->nTx && pindex->pprev->nChainTx)
                pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
            if (pindex->pprev->nStatus & BLOCK_FAILED_MASK) {
               pindex->nStatus |= BLOCK_FAILED_CHILD;
               if (pindexBestInvalid == NULL || pindex->nChainWork > pindexBestInvalid->nChainWork)
                   pindexBestInvalid = pindex;
            }
        }
        fWorkDone = true;
	//printf("going to insert %d\n", pindex->nStatus);
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE)){
	    //printf("insert\n");
	    pindex->nSequenceId = ++nBlockSequenceId;
            setBlockIndexValid.insert(pindex);
	}else{
	    //printf("Couldn't insert %d\n", pindex->nStatus);
	}
        const uint256 &hashBlock = pindex->GetBlockHash();
        multimap<uint256, CBlockIndex*>::iterator itadd = mapOrphanBlocksByPrev.lower_bound(hashBlock);
        while (itadd != mapOrphanBlocksByPrev.end() && itadd->first == hashBlock)
            vTodo.push_back(itadd++);
    }
    //printf("linkorphans dones\n");
    //printAffairs();
    return fWorkDone;
}

CBlockIndex * InsertBlockIndex(const uint256 &hash, const CBlockHeader &header)
{
    if (hash == 0)
        return NULL;

    CBlockIndex* pindexNew = NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        pindexNew = mi->second;

    if (pindexNew == NULL) {
        pindexNew = new CBlockIndex();
        mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
        pindexNew->phashBlock = &((*mi).first);
        pindexNew->nVersion = header.nVersion;
        pindexNew->hashMerkleRoot = header.hashMerkleRoot;
	pindexNew->hashAccountRoot = header.hashAccountRoot;
        pindexNew->nTime = header.nTime;
        pindexNew->nHeight = header.nHeight;
        pindexNew->nNonce = header.nNonce;
    }

    // Store hashPrev if orphan.
    //if (!pindexNew->fConnected)
    mapOrphanBlocksByPrev.insert(make_pair(header.hashPrevBlock, pindexNew)); 

    return pindexNew;
}

bool ForceNoTrie(){
 return false;//GetAdjustedTime() < (int64_t)pindexGenesisBlock->nTime || (GetAdjustedTime()-pindexGenesisBlock->nTime) < (MIN_HISTORY * 120);
}

bool static LoadBlockIndexDB()
{
    if (!pblocktree->LoadBlockIndexGuts())
        return false;

printAffairs();
    LinkOrphans();
printAffairs();

    boost::this_thread::interruption_point();

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    LogPrintf("LoadBlockIndexDB(): last block file = %i\n", nLastBlockFile);
    if (pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        LogPrintf("LoadBlockIndexDB(): last block file info: %s\n", infoLastBlockFile.ToString());

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("LoadBlockIndexDB(): transaction index %s\n", fTxIndex ? "enabled" : "disabled");

    // Load pointer to end of best chain
    LogPrintf("Best Block: %s\n",pviewTip->GetBestBlock().GetHex().c_str());
    std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(pviewTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return true;

    uint256 syncPoint=0;

    uint256 triePoint = pviewTip->GetBestBlock();


    pblocktree->ReadSyncPoint(syncPoint);
    printf("Sync point %s\n", syncPoint.GetHex().c_str());
 
    pindexGenesisBlock = mapBlockIndex[Params().HashGenesisBlock()];

    //Can't really do anything if genesis not loaded yet
    if(!pindexGenesisBlock){
	printf("GHash: %s\n", Params().HashGenesisBlock().GetHex().c_str());
	return true;
    }

    chainActive.SetTip(pindexGenesisBlock);
    chainHeaders.SetTip(pindexGenesisBlock); 

    //if genesis is really young set trieonline and write syncpoint to db
    if(syncPoint==0 && triePoint != 0 && triePoint != mapBlockIndex[Params().HashGenesisBlock()]){
	syncPoint = pindexGenesisBlock->GetBlockHash();
	pblocktree->WriteSyncPoint(syncPoint); 
	//init will activate trie?
    }

//    printAffairs();

    CValidationState state;
    ActivateBestHeader(state);
//	printAffairs();
//    chainHeaders.SetTip(it->second);
    if(syncPoint!=0){
	//Provisionally
	fTrieOnline=true;
	pindexSyncPoint = mapBlockIndex[syncPoint];
	pindexSyncPoint->fConnected = true;
	chainActive.SetTip(pindexSyncPoint);
    }

    //Do accelerated startup
#if 1
    if(chainHeaders.Height() > MIN_HISTORY){
	CBlockIndex *pindex = chainHeaders[chainHeaders.Height()-144];
    	//Have to make sure that pindex is reachable. 
	CBlockIndex *pmove = pindex;
	bool canMove = true;
	for(int i=144; i < MIN_HISTORY; i++){
	    if((pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS ||
            	(pindex->nStatus & BLOCK_FAILED_MASK)){
		canMove = false;
		break;
	    }
	    pmove = pmove->pprev;
	}
	if(canMove){
	    pmove = pindex;
	    for(int i=144; i < MIN_HISTORY; i++){
		pmove->fConnected=true;
   	    	pmove = pmove->pprev;
	    }
	    chainActive.SetTip(pindex);
	}
    }
#endif    

    CheckForkWarningConditions(true);

    LogPrintf("LoadBlockIndexDB(): trieOnline=%d hashBestChain=%s height=%d date=%s progress=%f\n",
        fTrieOnline, chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
        Checkpoints::GuessVerificationProgress(chainActive.Tip()));

    return true;
}

bool VerifyDB(int nCheckLevel, int nCheckDepth)
{
    if (chainActive.Tip() == NULL || chainActive.Tip()->pprev == NULL)
        return true;
#if 0

    // Verify blocks in the best chain
    if (nCheckDepth <= 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        if (pindex->nHeight < chainActive.Height()-nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex))
            return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state))
            return error("VerifyDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB() : *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.GetCacheSize() + pcoinsTip->GetCacheSize()) <= 2*nCoinCacheSize + 32000) {
            bool fClean = true;
            if (!DisconnectBlock(block, state, pindex, coins, &fClean))
                return error("VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += block.vtx.size();
        }
    }
    if (pindexFailure)
        return error("VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex))
                return error("VerifyDB() : *** ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!ConnectBlock(block, state, pindex, coins))
                return error("VerifyDB() : *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
#else
//    assert(0);
    return true;
#endif
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setBlockIndexValid.clear();
    chainActive.SetTip(NULL);
    pindexBestInvalid = NULL;
}

bool LoadBlockIndex()
{
    // Load block index from databases
    if (!fReindex && !LoadBlockIndexDB())
        return false;
    return true;
}


bool InitBlockIndex() {
    // Check whether we're already initialized
    if (chainActive.Genesis() != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", true);
    pblocktree->WriteFlag("txindex", fTxIndex);
    LogPrintf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        CValidationState state;
        try {
            CBlock &block = const_cast<CBlock&>(Params().GenesisBlock());
            // Start new block file
            if (!AcceptBlock(block, state))
                return error("LoadBlockIndex() : accepting genesis header failed");
        } catch(std::runtime_error &e) {
            return error("LoadBlockIndex() : failed to initialize block database: %s", e.what());
        }
	//If actually creating block the view needs to be built
//	if(!ActivateTrie(state))
//	    return error("LoadBlockIndex() : Trie rejected genesis block");

	return pviewTip->Flush();
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, chainActive.Genesis()));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                LogPrintf("| ");
            LogPrintf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                LogPrintf("| ");
            LogPrintf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            LogPrintf("| ");

        // print item
        CBlock block;
assert(0); //TODO: readblock can fail in MBC and is not even necessary for printing the tree
        blockCache.ReadBlockFromDisk(block, pindex);
        LogPrintf("%d (blk%05u.dat:0x%x)  %s  tx %" PRIszu "\n",
            pindex->nHeight,
            pindex->GetBlockPos().nFile, pindex->GetBlockPos().nPos,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block.GetBlockTime()),
            block.vtx.size());

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (chainActive.Next(vNext[i]))
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp)
{
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SIZE, MAX_BLOCK_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nStartByte = 0;
        if (dbp) {
            // (try to) skip already indexed part
            CBlockFileInfo info;
            if (pblocktree->ReadBlockFileInfo(dbp->nFile, info)) {
                nStartByte = info.nSize;
                blkdat.Seek(info.nSize);
            }
        }
        uint64_t nRewind = blkdat.GetPos();
        while (blkdat.good() && !blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[4];
                blkdat.FindByte(Params().MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, Params().MessageStart(), 4))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
                    continue;
            } catch (std::exception &e) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                blkdat.SetLimit(nBlockPos + nSize);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // process block
                if (nBlockPos >= nStartByte) {
                    CValidationState state;
                    if (!CheckBlock(block, state))
                        continue;

                    LOCK(cs_main);
                    if (dbp)
                        dbp->nPos = nBlockPos;

                    CBlockIndex *pindex = InsertBlockIndex(block.GetHash(), block);
                    if (!pindex->fConnected) {
                        pindex->nFile = dbp->nFile;
                        pindex->nDataPos = nBlockPos;
                        pindex->nUndoPos = 0;
                        pindex->nTx = block.vtx.size();
                        pindex->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
                    }
                    FindBlockPos(state, *dbp, nSize+8, 0, pindex->nTime, true);
                    if (LinkOrphans(&block.hashPrevBlock)) {
                        ActivateBestHeader(state);
                        ActivateBestChain(state);
                        pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
                    }
                }
            } catch (std::exception &e) {
                LogPrintf("%s : Deserialize or I/O error - %s", __PRETTY_FUNCTION__, e.what());
            }
        }
        fclose(fileIn);
    } catch(std::runtime_error &e) {
        AbortNode(_("Error: system error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}










//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode", false))
        strRPC = "test";

    if (!CLIENT_VERSION_IS_RELEASE)
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    if (fSecretChainAttack){
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: Unreachable blocks are being mined. Possible secret chain attack.");
    } else if (fLargeWorkForkFound)
    {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: The network does not appear to fully agree! Some miners appear to be experiencing issues.");
    }
    else if (fLargeWorkInvalidChainFound)
    {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: We do not appear to fully agree with our peers! You may need to upgrade, or other nodes may need to upgrade.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
            bool txInMap = false;
	    CTransaction tx;
	    uint256 block;
            txInMap = mempool.exists(inv.hash);
            return txInMap || GetTransaction(inv.hash,tx,block);
        }
    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}


void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                bool send = false;
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    // If the requested block is at a height below our last
                    // checkpoint, only serve it if it's in the checkpointed chain
                    int nHeight = mi->second->nHeight;
                    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
                    if (pcheckpoint && nHeight < pcheckpoint->nHeight) {
                        if (!chainActive.Contains(mi->second))
                        {
                            LogPrintf("ProcessGetData(): ignoring request for old block that isn't in the main chain\n");
                        } else {
                            send = true;
                        }
                    } else {
                        send = true;
                    }
                }
                if (send)
                {
                    // Send block from disk
                    CBlock block;
		    //If we cannot find the block body, just send the header in and let the node figure it out
                    if(!blockCache.ReadBlockFromDisk(block, (*mi).second)){
			block = mi->second->GetBlockHeader();
        		// we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
		    }
		    if (inv.type == MSG_BLOCK)
                        pfrom->PushMessage("block", block);
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage("merkleblock", merkleBlock);
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didnt send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    pfrom->PushMessage("tx", block.vtx[pair.first]);
                        }
                        // else
                            // no response
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, chainActive.Tip()->GetBlockHash()));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    CTransaction tx;
                    if (mempool.lookup(inv.hash, tx)) {
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            g_signals.Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();
    LogPrint("net", "received: %s (%" PRIszu " bytes)\n", strCommand, vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }

    State(pfrom->GetId())->nLastBlockProcess = GetTimeMicros();



    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->PushMessage("reject", strCommand, REJECT_DUPLICATE, string("Duplicate version message"));
            Misbehaving(pfrom->GetId(), 1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            LogPrintf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString(), pfrom->nVersion);
            pfrom->PushMessage("reject", strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION));
            pfrom->fDisconnect = true;
            return false;
        }

        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> pfrom->strSubVer;
            pfrom->cleanSubVer = SanitizeString(pfrom->strSubVer);
        }
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        if (!vRecv.empty())
            vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
        else
            pfrom->fRelayTxes = true;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);


        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

	//printf("inbound %d\n", pfrom->fInbound);
        if (!pfrom->fInbound)
        {
            // Advertise our address
	    //printf("nolisten %d initial %d\n", fNoListen, IsInitialBlockDownload());

            if (!fNoListen && !IsInitialBlockDownload() && (fTrieOnline || ForceNoTrie()))
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
		
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        LogPrintf("receive version message: %s: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->cleanSubVer, pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString(), addrFrom.ToString(), pfrom->addr.ToString());

        AddTimeData(pfrom->addr, nTime);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        if (vAddr.size() > 1000)
        {
            Misbehaving(pfrom->GetId(), 20);
            return error("message addr size() = %" PRIszu "", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64_t hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(pfrom->GetId(), 20);
            return error("message inv size() = %" PRIszu "", vInv.size());
        }

        LOCK(cs_main);

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            LogPrint("net", "  got inventory: %s  %s\n", inv.ToString(), fAlreadyHave ? "have" : "new");

            // Track requests for our stuff
            g_signals.Inventory(inv.hash);

            if (fAlreadyHave)
                continue;

            if (inv.type == MSG_BLOCK) {
                std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(inv.hash);
                if (it != mapBlockIndex.end()) {
                    CBlockIndex *pindex = it->second;
                    if (pfrom->pindexLastBlock == NULL || pindex->nChainWork >= pfrom->pindexLastBlock->nChainWork)
                        pfrom->pindexLastBlock = pindex;
                } else {
                    pfrom->hashLastBlock = inv.hash;
                }

		//Weird things can happen like we find out about a new block from peer A, then request it from peer B who doesn' have it,
		//then peer A disconnects and we get all confused. meanwhile peer B acquires it from somewhere else and broadcasts to us
		setBlockDontHave[pfrom->GetId()].erase(inv.hash);

                // First request the headers preceeding the announced block. In the normal fully-synced
                // case where a new block is announced that succeeds the current tip (no reorganization),
                // there are no such headers.
                // Secondly, and only when we are fully synced, we request the announced block afterwards,
                // to avoid an extra round-trip. Note that we *must* first ask for the headers, so by the
                // time the block arrives, the header chain leading up to it is already validated. Not
                // doing this will result in the received block being rejected as an orphan.
                pfrom->PushMessage("getheaders", CBlockLocator(chainHeaders.GetLocator()), inv.hash);
            }

            if (!IsInitialBlockDownload() && (fTrieOnline || ForceNoTrie()))
                pfrom->AskFor(inv);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            Misbehaving(pfrom->GetId(), 20);
            return error("message getdata size() = %" PRIszu "", vInv.size());
        }

        if (fDebug || (vInv.size() != 1))
            LogPrint("net", "received getdata (%" PRIszu " invsz)\n", vInv.size());

        if ((fDebug && vInv.size() > 0) || (vInv.size() == 1))
            LogPrint("net", "received getdata for: %s\n", vInv[0].ToString());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }

    else if (strCommand == "getslice")
    {
	uint256 hashBlock;
	uint160 left, right;
	vRecv >> hashBlock >> left >> right;

        if (fDebug)
            LogPrint("net", "received getslice for: %s l: %s, r: %s\n", hashBlock.GetHex().c_str(), left.GetHex().c_str(), right.GetHex().c_str());

	LOCK(cs_main);
        vector<uint8_t> data;

	//TODO: need to push various kinds of error conditions to remote

	//Quick check that we even have such a block first
	CBlockIndex *pindex=0;
	if(mapBlockIndex.find(hashBlock) == mapBlockIndex.end()){
	    pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    return error("block does not exists = %s", hashBlock.GetHex().c_str());
	}
	pindex = mapBlockIndex[hashBlock];

        if(!fTrieOnline){
	    pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    return error("in no condition to slice block = %s", hashBlock.GetHex().c_str());
	}

        if(!fTrieOnline || chainActive.Height() <= MIN_HISTORY){
	    pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    return error("in no condition to slice block = %s", hashBlock.GetHex().c_str());
	}

	if(pindex->nHeight + MIN_HISTORY + 10 < chainActive.Height()){
	    pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    return error("block too old for slicing block = %s", hashBlock.GetHex().c_str());
	}

        CBlock block;
	for(int i=pindex->nHeight; i < chainActive.Height()-MIN_HISTORY; i++){
            if(!blockCache.ReadBlockFromDisk(block, chainActive[i])){
		pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    	return error("no tx data available for block = %s", hashBlock.GetHex().c_str());
	    }
	}

	uint8_t *buf = new uint8_t[MAX_TRIE_SLICE_SIZE];
	uint32_t nodes=0;
	uint32_t sz = pviewTip->GetSlice(hashBlock, left, right, buf, MAX_TRIE_SLICE_SIZE,&nodes);
	if(sz){
	    data.assign(buf,buf+sz);
	    pfrom->PushMessage("slice",CSlice(hashBlock,left,right,data));
	    delete []buf;
	}else{
	    delete []buf;
	    pfrom->PushMessage("slice", CSlice(hashBlock, 0, 0, data));
	    return error("slice failed to materialize = %s", hashBlock.GetHex().c_str());
	}
	if(nodes==0){
	    LogPrintf("Node requesting infintesimal slices %d %d\n", nodes, sz);
	    Misbehaving(pfrom->GetId(), 50);
	}
    }

    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = chainActive.FindFork(locator);

        // Send the rest of the chain
        if (pindex)
            pindex = chainActive.Next(pindex);
        int nLimit = 500;
        LogPrint("net", "getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString(), nLimit);
	for (; pindex && pindex->nHeight <= chainActive.Height(); pindex = chainActive.Next(pindex))
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                LogPrint("net", "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                LogPrint("net", "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = chainActive.FindFork(locator);
            if (pindex)
                pindex = chainActive.Next(pindex);
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        vector<CBlock> vHeaders;
        int nLimit = 2000;
        LogPrint("net", "getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString());
        for (; pindex && pindex->nHeight <= chainActive.Height(); pindex = chainActive.Next(pindex))
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetTxID());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

	//Ignore incoming tx's until we are online
	if(!IsInitialBlockDownload() && (fTrieOnline || ForceNoTrie())){

            bool fMissingInputs = false;
            CValidationState state;
            if (AcceptToMemoryPool(mempool, state, tx, true, &fMissingInputs))
            {
//              mempool.check(pcoinsTip);
                RelayTransaction(tx, inv.hash);
                mapAlreadyAskedFor.erase(inv);
                vWorkQueue.push_back(inv.hash);
                vEraseQueue.push_back(inv.hash);


                LogPrint("mempool", "AcceptToMemoryPool: %s %s : accepted %s (poolsz %" PRIszu ")\n",
                   pfrom->addr.ToString(), pfrom->cleanSubVer,
                   tx.GetTxID().ToString(),
                   mempool.mapTx.size());

            }

            int nDoS = 0;
            if (state.IsInvalid(nDoS))
            {
                LogPrint("mempool", "%s from %s %s was not accepted into the memory pool: %s\n", tx.GetTxID().ToString(),
                  pfrom->addr.ToString(), pfrom->cleanSubVer,
                  state.GetRejectReason());
                pfrom->PushMessage("reject", strCommand, state.GetRejectCode(),
                               state.GetRejectReason(), inv.hash);
                if (nDoS > 0)
                    Misbehaving(pfrom->GetId(), nDoS);
            }
	}
    }
  
    else if (strCommand == "slice" && !fImporting && !fReindex)
    {
	CSlice slice;
	vRecv >> slice;

        LogPrint("net", "received slice %s %s %s\n", slice.m_block.ToString(), slice.m_left.ToString(), slice.m_right.ToString());
        printf("received slice %s %s %s\n", slice.m_block.ToString().c_str(), 
		slice.m_left.ToString().c_str(), slice.m_right.ToString().c_str());

	//Verify the slice if the one we requested	
	if(slice.m_block != pfrom->slice.m_block){
	     //Uh Ohs!!! --Misbehaving node
	     printf("Slice no match hash\n");
	     Misbehaving(pfrom->GetId(), 10);
	     trieSync.AbortSlice(pfrom->slice,false, AllNodes(), pfrom->GetId());
	}else{
	    if(slice.m_left < slice.m_right){
		//Slice purports to be good, check bounds
		if(slice.m_left == pfrom->slice.m_left && slice.m_right == pfrom->slice.m_right && slice.m_data.size()){
		    if(!trieSync.AcceptSlice(slice)){
			printf("Slice not accepted\n");
			Misbehaving(pfrom->GetId(), 10);
		    }else
			ActivateTrie();
		}else{
		    //Uh Ohs!!! Another bastard found.
		    printf("Wrong slice returned\n");
	     	    Misbehaving(pfrom->GetId(), 10);
		    trieSync.AbortSlice(pfrom->slice,false, AllNodes(), pfrom->GetId()); 
		}
	    }else{
		//Slice was rejected, could be from lack of history, slice too big or bad node
		//TODO: this will cause our trie slice size to halve. This is dangerous. Node can
		//Reject slices and effectively prevent us from coming online by confusing us as 
		//to the size of the trie. Forcing it to be downloading in trillions of seperate slices
		//Solution is probably to do statistics. If other node keep returning small slices
		//then we know something is up
		trieSync.AbortSlice(pfrom->slice,true, AllNodes(), pfrom->GetId()); //Use the no memory version
		printf("Abort slice\n");
	    }
	}
	printf("Done receive slice\n");
	pfrom->fSliced=false;
    }

    else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;

        LogPrint("net", "received block %s\n", block.GetHash().ToString());
	//printf("received block %ld\n", block.nHeight);
        // block.print();
        CInv inv(MSG_BLOCK, block.GetHash());

        {
            LOCK(cs_main);
            // Remember who we got this block from.
	    if(block.vtx.size())
            	mapBlockSource[inv.hash] = pfrom->GetId();
	    else{
		setBlockDontHave[pfrom->GetId()].insert(block.GetHash());
	    }
            std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(block.GetHash());
            if (it != mapBlockIndex.end()) {
                pfrom->setBlocksAskedFor.erase(it->second);
                mapBlocksAskedFor.erase(it->second);
            }
            mapAlreadyAskedFor.erase(inv);
        }

	if(block.vtx.size()){
            pfrom->AddInventoryKnown(inv);

            CValidationState state;
            ProcessBlock(state, &block,pfrom);

      	    int nDoS;
            if (state.IsInvalid(nDoS))
            	Misbehaving(pfrom->GetId(),nDoS);
	}
    }

    else if (strCommand == "headers" && !fImporting && !fReindex)
    {
        std::vector<CBlock> vBlocks;
        vRecv >> vBlocks;

        if (vBlocks.size() == 0)
            return true;

        CBlockIndex *pindexBefore = chainHeaders.Tip();

        CValidationState state;
        BOOST_FOREACH(const CBlock &block, vBlocks) {
	    LOCK(cs_main);
            if (!ProcessBlockHeader(state, &block)) {
                int nDoS;
                if (state.IsInvalid(nDoS))
                    Misbehaving(pfrom->GetId(),nDoS);
                break;
            }
        }

        if (chainHeaders.Tip() != pindexBefore) {
            LogPrint("net", "received %i headers: %s  height=%i->%i  log2_work=%.8g  date=%s\n",
              (int)vBlocks.size(), chainHeaders.Tip()->GetBlockHash().ToString().c_str(),
              pindexBefore ? pindexBefore->nHeight : -1, chainHeaders.Height(),
              log(chainHeaders.Tip()->nChainWork.getdouble())/log(2.0),
              DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainHeaders.Tip()->GetBlockTime()).c_str());

            // Assume the headers are in order, so only check the last one to update pindexLastBlock.
            std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(vBlocks.back().GetHash());
            if (it != mapBlockIndex.end()) {
                CBlockIndex *pindex = it->second;
                if (pfrom->pindexLastBlock == NULL || pindex->nChainWork >= pfrom->pindexLastBlock->nChainWork)
                    pfrom->pindexLastBlock = it->second;
            }

            // Continue syncing from this node.
            pfrom->PushMessage("getheaders", chainHeaders.GetLocator(), uint256(0));
        }
    }

    else if (strCommand == "getaddr")
    {
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        LOCK2(cs_main, pfrom->cs_filter);

        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        BOOST_FOREACH(uint256& hash, vtxid) {
            CInv inv(MSG_TX, hash);
            CTransaction tx;
            bool fInMemPool = mempool.lookup(hash, tx);
            if (!fInMemPool) continue; // another thread removed since queryHashes, maybe...
            if ((pfrom->pfilter && pfrom->pfilter->IsRelevantAndUpdate(tx, hash)) ||
               (!pfrom->pfilter))
                vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ) {
                pfrom->PushMessage("inv", vInv);
                vInv.clear();
            }
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "ping")
    {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
    }


    else if (strCommand == "pong")
    {
        int64_t pingUsecEnd = GetTimeMicros();
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere, cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere, cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint("net", "pong %s %s: %s, %x expected, %x received, %" PRIszu " bytes\n",
                pfrom->addr.ToString(),
                pfrom->cleanSubVer,
                sProblem,
                pfrom->nPingNonceSent,
                nonce,
                nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                Misbehaving(pfrom->GetId(), 10);
            }
        }
    }


    else if (strCommand == "filterload")
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
            // There is no excuse for sending a too-large filter
            Misbehaving(pfrom->GetId(), 100);
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "filteradd")
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            Misbehaving(pfrom->GetId(), 100);
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
                Misbehaving(pfrom->GetId(), 100);
        }
    }


    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = new CBloomFilter();
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "reject")
    {
        if (fDebug)
        {
            string strMsg; unsigned char ccode; string strReason;
            vRecv >> strMsg >> ccode >> strReason;

            ostringstream ss;
            ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

            if (strMsg == "block" || strMsg == "tx")
            {
                uint256 hash;
                vRecv >> hash;
                ss << ": hash " << hash.ToString();
            }
            // Truncate to reasonable length and sanitize before printing:
            string s = ss.str();
            if (s.size() > 111) s.erase(111, string::npos);
            LogPrint("net", "Reject %s\n", SanitizeString(s));
        }
    }

    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //    LogPrintf("ProcessMessages(%"PRIszu" messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return fOk;

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    LogPrintf("ProcessMessages(message %u msgsz, %"PRIszu" bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, Params().MessageStart(), MESSAGE_START_SIZE) != 0) {
            LogPrintf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            LogPrintf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            LogPrintf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand, nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv);
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            pfrom->PushMessage("reject", strCommand, REJECT_MALFORMED, string("error parsing message"));
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                LogPrintf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand, nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                LogPrintf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand, nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted) {
            throw;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            LogPrintf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand, nMessageSize);

        break;
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSendMsg.empty()) {
            // Ping automatically sent as a keepalive
            pingSend = true;
        }
        if (pingSend) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                RAND_bytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->nPingNonceSent = nonce;
            pto->fPingQueued = false;
            // Take timestamp as close as possible before transmitting ping
            pto->nPingUsecStart = GetTimeMicros();
            pto->PushMessage("ping", nonce);
        }

        // Address refresh broadcast
        static int64_t nLastRebroadcast;
        if (!IsInitialBlockDownload() && (fTrieOnline || ForceNoTrie()) && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }

        TRY_LOCK(cs_main, lockMain);
        if (!lockMain)
            return true;

        CNodeState &state = *State(pto->GetId());
        if (state.fShouldBan) {
            if (pto->addr.IsLocal())
                LogPrintf("Warning: not banning local node %s!\n", pto->addr.ToString());
            else {
		printf("Ban\n");
                pto->fDisconnect = true;
                CNode::Ban(pto->addr);
            }
            state.fShouldBan = false;
        }

        BOOST_FOREACH(const CBlockReject& reject, state.rejects)
            pto->PushMessage("reject", (string)"block", reject.chRejectCode, reject.strRejectReason, reject.hashBlock);
        state.rejects.clear();

        // Start block sync
	//printf("Should send getheaders\n");
        if (pto->fStartSync && !fImporting && !fReindex) {
            pto->fStartSync = false;
	    //printf("Sending getheaders %d\n", chainHeaders.Height());
            pto->PushMessage("getheaders", chainHeaders.GetLocator(), uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !fLoading && !IsInitialBlockDownload() && (fTrieOnline || ForceNoTrie()))
        {
            g_signals.Broadcast();
        }

        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);

        // Update pindexLastBlock
    	if (pto->hashLastBlock != 0) {
            std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(pto->hashLastBlock);
            if (it != mapBlockIndex.end()) {
                if (pto->pindexLastBlock == NULL || it->second->nChainWork >= pto->pindexLastBlock->nChainWork)
                    pto->pindexLastBlock = it->second;
                pto->hashLastBlock = 0;
            }
        }

        // Detect stalled peers. Require that blocks are in flight, we haven't
        // received a (requested) block in one minute, and that all blocks are
        // in flight for over two minutes, since we first had a chance to
        // process an incoming block.

        vector<CInv> vGetData;
        int64_t nNow = GetTimeMicros();

    	// Update pindexLastBlock
	if (pto->hashLastBlock != 0) {
            std::map<uint256, CBlockIndex*>::iterator it = mapBlockIndex.find(pto->hashLastBlock);
            if (it != mapBlockIndex.end()) {
            	if (pto->pindexLastBlock == NULL || it->second->nChainWork >= pto->pindexLastBlock->nChainWork)
                    pto->pindexLastBlock = it->second;
                pto->hashLastBlock = 0;
            }
     	}

        //
        // Message: getdata (blocks)
        //

        //printf("Do get blocks\n");
        {
     	int nLastHeight = std::max(chainHeaders.Height(), pto->pindexLastBlock ? pto->pindexLastBlock->nHeight : pto->nStartingHeight);
    	if (chainActive.Tip() && !fReindex && !fImporting && pto->nServices & NODE_NETWORK) {
	    list<CBlockIndex*> toremove;
            BOOST_FOREACH(PAIRTYPE(CBlockIndex*, uint64_t) item, mapBlocksAskedFor){
		if(item.second + 60 < (uint64_t)GetTime())
		   toremove.push_back(item.first);
	    }
	    BOOST_FOREACH(CBlockIndex* item, toremove){
        	LOCK(cs_vNodes);
        	BOOST_FOREACH(CNode* pnode, vNodes){
		    if(pnode->setBlocksAskedFor.count(item)){
                    	LogPrintf("Block download stalled by %s; disconnecting\n", pnode->addr.ToString().c_str());
                    	pnode->fDisconnect = true;
		    	pnode->setBlocksAskedFor.erase(item);
		    }
		}
		mapBlocksAskedFor.erase(item);
	    }

	    //printf("blocks asked for: %ld setHeightMissing: %ld\n", pto->setBlocksAskedFor.size(), setHeightMissing.size());
	    //if(mapBlocksAskedFor.size())
	    //	printf("Time: %ld %ld\n", mapBlocksAskedFor.begin()->second, GetTime());
	    BOOST_FOREACH(int nHeight, setHeightMissing){
                if ((int)pto->setBlocksAskedFor.size() >= MAX_BLOCKS_IN_TRANSIT_PER_PEER)
		    break;

            	CBlockIndex *pindex = chainHeaders[nHeight];
            	if(mapBlocksAskedFor.count(pindex))
		    continue;

		//printf("Requesting %s %ld\n", pindex->GetBlockHash().GetHex().c_str(), pindex->nHeight);

		if (setBlockDontHave[pto->GetId()].count(pindex->GetBlockHash()))
		    continue;
#if 0 //TODO: this is a security problem but we need it to keep the primary node running
                if (pto->fInbound && nHeight+100 < chainHeaders.Height())
                    break;
#endif
//            	setHeightMissing.erase(nHeight);
            	pto->setBlocksAskedFor.insert(pindex);
            	mapBlocksAskedFor[pindex] = GetTime();
            	vGetData.push_back(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            }
            if (vGetData.size())
            	LogPrintf("Requesting %i blocks from %s\n", (int)vGetData.size(), pto->addr.ToString().c_str());
    	}
 	}

	//
	// Message: getdata (trie slice)
	//
	//printf("online %d\n", fTrieOnline);

    	//if(!trieOnline)
    	//printf("CanSync %d %ld %d\n", trieSync.CanSync(), setHeightMissing.size(), IsInitialBlockDownload());
	if(trieSync.CanSync() && !fTrieOnline && !ForceNoTrie() && pto->nVersion > BROKEN_SLICE_VERSION){
	    //If slice requested from peer. check for stall
	    if(pto->fSliced){
		if(pto->sliceTime > GetTime() + 60){
		    printf("Stalled somehow!\n");
                    LogPrintf("Slice download stalled by %s; disconnecting\n", pto->addr.ToString().c_str());
                    pto->fDisconnect = true;
		}
	    }else{
	        //printf("Need some slice action!!!!!\n");
	        //request a slice
		CSlice slice = trieSync.GetSlice(pto->id);    
		if(slice.m_right > slice.m_left){ //Sometimes no slices are available
		    pto->PushMessage("getslice",slice.m_block,slice.m_left,slice.m_right);
		    printf("Getting slice: %s %s %s\n", slice.m_block.GetHex().c_str(), slice.m_left.GetHex().c_str(),slice.m_right.GetHex().c_str());
		    pto->fSliced=true;
		    pto->sliceTime = GetTime();
		    pto->slice = slice;
		}else
		    ActivateTrie();
	    }
	}

        //
        // Message: getdata (non-blocks)
        //
        while (!pto->fDisconnect && !pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (fDebug)
                    LogPrint("net", "sending getdata: %s\n", inv.ToString());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        std::map<uint256, CBlockIndex*>::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
