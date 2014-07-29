// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "core.h"
#include "main.h"
#include "net.h"
#ifdef ENABLE_WALLET
#include "wallet.h"
#endif
//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

static bool fSoloMine=false;

// Some explaining would be appreciated
class COrphan
{
public:
    const CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(const CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        LogPrintf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            LogPrintf("   setDependsOn %s\n", hash.ToString());
    }
};


uint64_t nLastBlockTx = 0;
uint64_t nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, const CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

string gen_random() {
    char s[64];
    memset(s,0,sizeof(s));
    int len = 16;

    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
    return string(s);
}

CBlockTemplate* CreateNewBlock(uint160 pubKey)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].SetNull();
    txNew.vout.resize(1);
    txNew.vout[0].pubKey = pubKey;//build transaction!!!!;
    string msg = gen_random();
    txNew.msg = vector<char>(msg.begin(),msg.end());

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end


    // Collect memory pool transactions into the block
    int64_t nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = chainActive.Tip();

    	// Largest block you're willing to create:
    	unsigned int nBlockMaxSize = GetNextMaxSize(pindexPrev);
    	// Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    	nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    	// How much of the block should be dedicated to high-priority transactions,
    	// included regardless of the fees they pay
    	unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", DEFAULT_BLOCK_PRIORITY_SIZE);
    	nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        bool fPrintPriority = GetBoolArg("-printpriority", false);

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
	map<uint160,uint64_t> mapBalances;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTxMemPoolEntry>::iterator mi = mempool.mapTx.begin();
             mi != mempool.mapTx.end(); ++mi)
        {
	    //printf("Analyzing tx\n");
            const CTransaction& tx = mi->second.GetTx();
            if (tx.IsCoinBase() || !IsFinalTx(tx, pindexPrev->nHeight + 1))
                continue;

	    if(TxExists(tx.GetTxID()))
		continue;

            double dPriority = 0;
            int64_t nTotalIn = 0;
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
		    pviewTip->Limit(txin.pubKey,limit,pindexPrev->nHeight+1);
		    if(balance > limit)
			balance = limit;
		    if(balance < txin.nValue){
			fMissingInputs=true;
			break;
		    }
		    mapBalances[txin.pubKey] = balance - txin.nValue;
		}
                nTotalIn += txin.nValue;
                int nConf = pviewTip->CoinAge(txin.pubKey);
                dPriority += (double)txin.nValue * nConf;
            }
            if (fMissingInputs) continue;

	    bool fCantCreate=false;
	    BOOST_FOREACH(const CTxOut& txout, tx.vout){
		uint64_t balance=0;
		if(!pviewTip->Balance(txout.pubKey,balance) && txout.nValue < tx.GetFee()){
		    fCantCreate=true;
		    break;
		}
	    }
	    if(fCantCreate) continue;

            // Priority is sum(valuein * age) / modified_txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority = tx.ComputePriority(dPriority, nTxSize);

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &mi->second.GetTx()));
        }

        // Collect transactions into block
        uint64_t nBlockSize = 1000;
        uint64_t nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
	//printf("Tx's: %ld\n", vecPriority.size());

	set<uint160> setTxOps;
	set<uint160> setLimits;

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            const CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize){
		printf("Too big\n");
                continue;
	    }

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = GetLegacySigOpCount(tx);

            // Skip free transactions:
            if (dFeePerKb < CTransaction::nMinRelayTxFee){
		printf("Was free\n");
                continue;
	    }

	    // Age limits
	    if(tx.fSetLimit){
		if(setTxOps.count(tx.vin[0].pubKey) || setLimits.count(tx.vin[0].pubKey))
		    continue; //Can't have a block where a tx and set limit exist simultaneously 

		//Limit transactions always valid now
		setLimits.insert(tx.vin[0].pubKey);
	    }else{
	    	BOOST_FOREACH(const CTxIn& txin, tx.vin){
		     if(setLimits.count(txin.pubKey))
			continue;
	    	}
	    }

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || !AllowFree(dPriority)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            int64_t nTxFees = tx.GetValueIn()-tx.GetValueOut();

	    if(tx.GetValueIn() < tx.GetValueOut()){
		printf("Value foobar\n");
		continue;
	    }

            CValidationState state;
            //Double check signatures
            if (!CheckInputs(tx, state))
                continue;

	    BOOST_FOREACH(const CTxIn& txin, tx.vin){
		setTxOps.insert(txin.pubKey);
	    }

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                LogPrintf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString());
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        LogPrintf("CreateNewBlock(): total size %u\n", nBlockSize);

	uint64_t balance=0;
	pviewTip->Balance(0,balance);
        pblock->vtx[0].vout[0].nValue = GetBlockValue(balance, nFees);
	pblock->vtx[0].vin[0].nValue = pblock->vtx[0].vout[0].nValue;
        pblocktemplate->vTxFees[0] = -nFees;

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        UpdateTime(*pblock, pindexPrev);
        //pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
	pblock->nHeight	       = pindexPrev->nHeight+1;
        pblock->vtx[0].vin[0].scriptSig.clear();
	pblock->vtx[0].nLockHeight = pblock->nHeight;
        if(!pviewTip->HashForBlock(*pblock, pblock->hashAccountRoot)){
		return 0;
	}
	LogPrintf("Mining for trie hash: %s\n", pblock->hashAccountRoot.GetHex().c_str());
        pblocktemplate->vTxSigOps[0] = GetLegacySigOpCount(pblock->vtx[0]);
	pblock->hashMerkleRoot = pblock->BuildMerkleTree();

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CValidationState state;
        if (!ConnectBlock(*pblock, state, &indexDummy, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}

#ifdef ENABLE_WALLET
//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//
double dHashesPerSec = 0.0;
int64_t nHPSTimerStart = 0;

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// It operates on big endian data.  Caller does the byte reversing.
// All input buffers are 16-byte aligned.  nNonce is usually preserved
// between calls, but periodically or if nNonce is 0xffff0000 or above,
// the block is rebuilt and nNonce starts over at zero.
//
#if 0
unsigned int static ScanHash_CryptoPP(char* pmidstate, char* pdata, char* phash1, char* phash, unsigned int& nHashesDone)
{
    unsigned int& nNonce = *(unsigned int*)(pdata + 12);
    for (;;)
    {
        // Crypto++ SHA256
        // Hash pdata using pmidstate as the starting state into
        // pre-formatted buffer phash1, then hash phash1 into phash
        nNonce++;
        SHA256Transform(phash1, pdata, pmidstate);
        SHA256Transform(phash, phash1, pSHA256InitState);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((unsigned short*)phash)[14] == 0)
            return nNonce;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xffff) == 0)
        {
            nHashesDone = 0xffff+1;
            return (unsigned int) -1;
        }
        if ((nNonce & 0xfff) == 0)
            boost::this_thread::interruption_point();
    }
}
#endif

bool CheckWork(CBlock* pblock, uint256 hashTarget, CWallet& wallet)
{
    uint256 hash = pblock->GetHash();

    if (hash > hashTarget)
        return false;

    //// debug print
    LogPrintf("BitcoinMiner:\n");
    LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashTarget.GetHex());
    pblock->print();
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitcoinMiner : generated block is stale");
    }
        
    // Track how many getdata requests this block gets
    {
      	LOCK(wallet.cs_wallet);
        wallet.mapRequestCount[pblock->GetHash()] = 0;
    }

    // Process this block the same as if we had received it from another node
    CValidationState state;
    if (!ProcessBlock(state, pblock))
        return error("BitcoinMiner : ProcessBlock, block not accepted");

    return true;
}

void static BitcoinMiner(CWallet *pwallet)
{
    LogPrintf("BitcoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("bitcoin-miner");

    // Each thread has its own key and counter
    try { while (true) {
        if (Params().NetworkID() != CChainParams::REGTEST) {
            // Busy-wait for the network to come online so we don't waste time mining
            // on an obsolete chain. In regtest mode we expect to fly solo.
            while (vNodes.empty() && !fSoloMine)
                MilliSleep(1000);
        }

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
        CBlockIndex* pindexPrev = chainActive.Tip();

        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(pwallet->GetDefaultPubKey()));
        if (!pblocktemplate.get()){
		MilliSleep(100);
		continue;
	}
        CBlock *pblock = &pblocktemplate->block;

        LogPrintf("Running BitcoinMiner with %" PRIszu " transactions in block (%u bytes)\n", pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Search
        //
        int64_t nStart = GetTime();
        uint256 hashTarget = UpdateTime(*pblock, pindexPrev);
	uint256 bestHash;
	memset(&bestHash,0xFF,32);
	LogPrintf("Target: %s\n", hashTarget.GetHex().c_str());
        while (true)
        {
            unsigned int nHashesDone = 0;
	    RAND_bytes((unsigned char *)&pblock->nNonce, sizeof(pblock->nNonce));
	    uint256 hash = pblock->GetHash();
            while (hash > hashTarget) {
            		++pblock->nNonce;
			hash = pblock->GetHash();
			if(hash < bestHash){
				bestHash=hash;
				//printf("New best: %s\n", hash.GetHex().c_str());
			}
			if ((pblock->nNonce & 0xfff) == 0){
            			boost::this_thread::interruption_point();
			        if ((pblock->nNonce & 0xffff) == 0) {
					//Weird thing here. Since we are starting with random nonce
					//On average the initial nonce will be 0x8000 and not 0xFFFF
					//so only half of those were actually checked
            				nHashesDone = (0xffff+1) >> 1;
					break;
				}
			}
            }

                if (hash <= hashTarget)
                {
                    // Found a solution

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, hashTarget, *pwallet);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);

                    // In regression test mode, stop mining after a block is found. This
                    // allows developers to controllably generate a block on demand.
                    if (Params().NetworkID() == CChainParams::REGTEST)
                        throw boost::thread_interrupted();

                    break;
                }


            // Meter hashes/sec
            static int64_t nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter += nHashesDone;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64_t nLogTime;
                        if (GetTime() - nLogTime > 30 * 60)
                        {
                            nLogTime = GetTime();
                            LogPrintf("hashmeter %6.0f khash/s\n", dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();
            if (vNodes.empty() && !fSoloMine)
                break;
            if (pblock->nNonce >= 0xffff000000000000ULL)
                break;
            if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != chainActive.Tip())
                break;

            // Update nTime every few seconds
            // Changing pblock->nTime can change work required on testnet:
            hashTarget = UpdateTime(*pblock, pindexPrev);
        }
    } }
    catch (boost::thread_interrupted)
    {
        LogPrintf("BitcoinMiner terminated\n");
        throw;
    }
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet, int nThreads)
{
    static boost::thread_group* minerThreads = NULL;
    fSoloMine = GetBoolArg("-solomine", false);


    if (nThreads < 0) {
        if (Params().NetworkID() == CChainParams::REGTEST)
            nThreads = 1;
        else
            nThreads = boost::thread::hardware_concurrency();
    }

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, pwallet));
}

#endif

