// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "txdb.h"
#include "init.h"
#include "wallet.h"	

extern map<uint256, CBlockIndex*> mapBlockIndex;

CCriticalSection cs_trie;

TrieView::TrieView(){
    //TODO: load the crap from file
    m_bestBlock = 0;  
    m_root = 0;

    boost::filesystem::path pathDebug = GetDataDir() / "trie.dat";
    printf("Opening %s\n", pathDebug.string().c_str());

    FILE* filein = fopen(pathDebug.string().c_str(), "rb");
    if(!filein)
	return;

    assert(fread(&m_bestBlock,1,32,filein)>0);
    uint32_t sz=0;
    assert(fread(&sz,1,4,filein)>0);
    uint8_t *buf = (uint8_t*)malloc(sz);
    assert(fread(buf,sz,1,filein)>0);
    fclose(filein);
    m_root = TrieNode::Deserialize(buf,sz);
    free(buf);

    LogPrintf("Loaded trie at %s %d\n", m_bestBlock.GetHex().c_str(), sz);
}

void TrieView::Force(TrieNode *root, uint256 block){
    if(m_root)
	delete m_root;
    m_root = root;
    m_bestBlock = block;
    Flush();
}

static void getSet(CBlockIndex *pindex, set<CBlockIndex*> &theSet){
	while(pindex){
		theSet.insert(pindex);
		pindex = pindex->pprev;
	}
}

static void sortSet(set<CBlockIndex*> &theSet, vector<pair<uint64_t,CBlockIndex*> > &theVector){
	theVector.reserve(theSet.size());
	set<CBlockIndex*>::iterator it;
	for(it=theSet.begin(); it!=theSet.end(); it++){
		theVector.push_back(make_pair((*it)->nHeight,*it));
	}
	sort(theVector.begin(),theVector.end());
}

bool TrieView::Activate(CBlockIndex *pindex, uint256 &badBlock){
    LOCK(cs_main);
    //Find shortest path to the validated Trie
    set<CBlockIndex*> newSet, oldSet, oldSetCopy;
    getSet(pindex,newSet);
    getSet((*mapBlockIndex.find(m_bestBlock)).second,oldSet);

    LogPrintf("Activate %s\n", pindex->GetBlockHeader().GetHash().GetHex().c_str());

    //TODO: it is probably possible to use CChain to do most of this work

    //we need the sets ordered by height or else it will be impossible to apply
    //in the correct order
 
    printf("OS %ld NS %ld\n", oldSet.size(), newSet.size());

    oldSetCopy = oldSet;
    set<CBlockIndex*>::iterator it;
    for(it = newSet.begin(); it != newSet.end(); it++){
        oldSet.erase(*it);
    }

    for(it = oldSetCopy.begin(); it != oldSetCopy.end(); it++){
	newSet.erase(*it);
    }
    
    //TODO: if the sets are longer than cycle time we have detected a pre cycle fork here. 
    //Supposed to break or whatever

    //make sure we have transaction data for the sets or else it must be requested
    //before activation is possible (including invertible data) - situation impossible

    vector<pair<uint64_t,CBlockIndex*> > newVector, oldVector;
    sortSet(oldSet,oldVector);
    sortSet(newSet,newVector);
    reverse(oldVector.begin(), oldVector.end());
	
    vector<pair<uint64_t,CBlockIndex*> >::iterator it2;
    for(it2 = oldVector.begin(); it2 != oldVector.end(); it2++){
    	CBlockUndo blockUndo;
    	CDiskBlockPos pos = (*it2).second->GetUndoPos();
    	if (pos.IsNull())
            return error("DisconnectBlock() : no undo pos vailable");
    	if (!blockUndo.ReadFromDisk(pos, (*it2).second->GetBlockHash()))
            return error("DisconnectBlock() : failure reading undo data");

	list<CTxUndo> undos;
	for(vector<CTxUndo>::iterator it3=blockUndo.vtxundo.begin(); it3!=blockUndo.vtxundo.end(); it3++){
	    undos.push_back(*it3);
	}
	Unapply(undos);
	m_bestBlock = it2->second->GetBlockHash();
    }    

    for(it2 = newVector.begin(); it2 != newVector.end(); it2++){
        //if for some reason we have a failure, we need to unwind all previously 
        //completed actions before return
	if(!Apply((*it2).second)){
		badBlock = (*it2).second->GetBlockHash();
		return false;	
	}
	m_bestBlock = it2->second->GetBlockHash();		
    }
    m_bestBlock = pindex->GetBlockHeader().GetHash();
    return true;
}

#define MIN_BALANCE 1

bool TrieView::TempApply(CBlock block, list<CTxUndo> &undos){
    map<uint160,uint64_t> limits;
    set<uint160> setLimit, setTxIn;

    BOOST_FOREACH(const CTransaction &tx, block.vtx){
	if(tx.IsCoinBase()){
	    TrieNode* node = TrieEngine::Find(0, m_root);
	    uint64_t coinb=0;
	    if(node)
		coinb = node->Balance();  
    	    if (tx.vout[0].nValue > (uint64_t)GetBlockValue(coinb, block.GetFees())){
		LogPrintf("Coinbase paid too much!\n");
		return false;
	    }
	}


	BOOST_FOREACH(const CTxIn& txin, tx.vin){
	    TrieNode* node = TrieEngine::Find(txin.pubKey, m_root);
	    if(!node){
		LogPrintf("Failed to find node for %s\n", txin.pubKey.GetHex().c_str());
		return false;
	    }
	    CTxUndo undo(node->Key());
	    undo.m_balance = node->Balance();
	    undo.m_age = node->Age();
	    undo.m_limit = node->Limit();
	    undo.m_futurelimit = node->FutureLimit();

	    if(!tx.fSetLimit){  //Fee on set limit is allowed to surpass limit field to prevent stuck accounts
		if(limits.find(node->Key()) == limits.end()){
		    if(txin.nValue > node->Limit()){
			LogPrintf("Tried to spend past limit %s %ld %ld\n", txin.pubKey.GetHex().c_str(), txin.nValue, node->Limit());
			return false;
		    }
		    limits[node->Key()] = node->Limit() - txin.nValue;
		}else{
		    if(txin.nValue > limits[node->Key()]){
			LogPrintf("Tried to spend past limit %s %ld %ld\n", txin.pubKey.GetHex().c_str(), txin.nValue, node->Limit());
			return false;
		    }		 
		    limits[node->Key()] -= txin.nValue;
		}
	    }

	    if(txin.nValue > node->Balance()){
		LogPrintf("Source has insufficient balance %s %ld %ld\n", txin.pubKey.GetHex().c_str(), txin.nValue, node->Balance());
		//m_root->Print();
		return false;
	    }

	    if(!tx.fSetLimit && setLimit.count(txin.pubKey)){
		LogPrintf("Limit switch and transaction in same block\n");
		return false;	
	    }

	    if(tx.fSetLimit && tx.nLimitValue < node->Limit() && setTxIn.count(txin.pubKey)){
		LogPrintf("Limit switch and transaction in same block\n");
		return false;
	    }

	    if(block.nHeight - node->Age() > MIN_LIMIT_TIME){
		if(node->FutureLimit() != node->Limit() && setTxIn.count(txin.pubKey)){
		    LogPrintf("Limit switch and transaction in same block\n");
		    return false;
		}
 	        node->SetLimit(node->FutureLimit());		
	    }

	    //No node updates until tx guaranteed to succeed!!!
	    if(tx.fSetLimit){
		node->SetFutureLimit(tx.nLimitValue);
		//Instant update if limit is lower
		if(node->FutureLimit() < node->Limit())
		    node->SetLimit(node->FutureLimit());

		setLimit.insert(txin.pubKey);
	    }else{
		setTxIn.insert(txin.pubKey);
	    }
	    
	    node->SetAge(block.nHeight);
		    
	    node->SetBalance(node->Balance() - txin.nValue);
	    if(node->Balance() < MIN_BALANCE){
		TrieEngine::Remove(&m_root,node);
		undo.m_destroy=true;
	    }
	    undos.push_back(undo);
	}

        BOOST_FOREACH(const CTxOut& txout, tx.vout){
	    TrieNode* node = TrieEngine::Find(txout.pubKey, m_root);
	    if(node){
		CTxUndo undo(node->Key());
		undo.m_balance = node->Balance();
		undo.m_age = node->Age();
		undo.m_limit = node->Limit();
		undo.m_futurelimit = node->FutureLimit();
		undos.push_back(undo);
		//node->SetAge(block.nHeight); //No age update on deposit
		node->SetBalance(node->Balance() + txout.nValue);
	    }else{
		node = new TrieNode(NODE_LEAF);
		node->SetKey(txout.pubKey);
		node->SetAge(block.nHeight);
		node->SetBalance(node->Balance() + txout.nValue);
		TrieEngine::Insert(&m_root,node);
		CTxUndo undo(node->Key());
		undo.m_create = true;
		undos.push_back(undo);
	    }
        }
    }
    reverse(undos.begin(),undos.end());
    return true;
}

bool TrieView::Unapply(list<CTxUndo> &undos){
    list<CTxUndo>::iterator it;
    for(it=undos.begin(); it!= undos.end(); it++){
	CTxUndo undo = *it;
	if(undo.m_create){
	    TrieNode *node = TrieEngine::Find(undo.m_key, m_root);
	    assert(node);
	    TrieEngine::Remove(&m_root,node);
	    //delete node;
	}else if(undo.m_destroy){
	    TrieNode *node = new TrieNode(NODE_LEAF);
	    node->SetAge(undo.m_age);
	    node->SetKey(undo.m_key);
	    node->SetBalance(undo.m_balance);
	    node->SetLimit(undo.m_limit);
	    node->SetFutureLimit(undo.m_futurelimit);
	    TrieEngine::Insert(&m_root,node);
	}else{
	    TrieNode *node = TrieEngine::Find(undo.m_key, m_root);
	    node->SetAge(undo.m_age);
	    node->SetKey(undo.m_key);
	    node->SetBalance(undo.m_balance);
	    node->SetLimit(undo.m_limit);
	    node->SetFutureLimit(undo.m_futurelimit);
	}
    }
    return true;
}

bool TrieView::HashForBlock(CBlock block, uint256 &hash){
    LOCK(cs_main);

    if(m_bestBlock != block.hashPrevBlock){
	LogPrintf("HashForBlock(): m_bestBlock hashPrevBlock mismatch!");
	return false;
    }
    list<CTxUndo> undos;
    if(!TempApply(block,undos)){
	Unapply(undos);
	return false;
    }   
    hash = m_root->Hash();
    Unapply(undos);
    return true;
}

uint64_t TrieView::Accounts(){
    return m_root->Children();
}

void backtrace();

//Apply the tx's in pindex to the trie. This assume the current state of the trie is pindex->pprev. This code will also generate the undo
//block and save it to the trie if possible. Pindex can be invalid!. This code will detect and unwind an invalid tx set. 
bool TrieView::Apply(CBlockIndex *pindex){
    CBlock block;
    assert(blockCache.ReadBlockFromDisk(block, pindex));   

    //printf("WTF: %s %s\n", pindex->hashAccountRoot.GetHex().c_str(), block.hashAccountRoot.GetHex().c_str());
    //backtrace();

    //we must generate invertible data of the block at this point
    //otherwise trie can not be unwound
    list<CTxUndo> undos;
    if(!TempApply(block,undos)){
	LogPrintf("Could not apply tx's!");
	Unapply(undos);
	return false;
    }

    if(m_root->Hash()!=block.hashAccountRoot){
	LogPrintf("Master hash mismatch: %s %s %s\n", pindex->GetBlockHash().GetHex().c_str(),
		m_root->Hash().GetHex().c_str(), block.hashAccountRoot.GetHex().c_str());
	Unapply(undos);
	return false;
    }

    // Write undo information to disk
    CBlockUndo blockundo;
    for(list<CTxUndo>::iterator it = undos.begin(); it!= undos.end(); it++)
	blockundo.vtxundo.push_back(*it);
    if (pindex->GetUndoPos().IsNull() || (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
    {
        if (pindex->GetUndoPos().IsNull()) {
            CDiskBlockPos pos;
	    CValidationState state;
            if (!FindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock() : FindUndoPos failed");
            if (!blockundo.WriteToDisk(pos, block.GetBlockHeader().GetHash()))
                return error("Failed to write undo data");

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS;

        CDiskBlockIndex blockindex(pindex);
        if (!pblocktree->WriteBlockIndex(blockindex))
            return error("Failed to write block index");
    }

    m_bestBlock = pindex->GetBlockHeader().GetHash();   
    return true;
}

bool TrieView::BalancesAt(CBlockIndex* pindex, vector<uint160> hashes, vector<CActInfo> &balances){
    LOCK(cs_main);
    uint256 oldHash = m_bestBlock;

    //Blast from the past
    uint256 bad;
    assert(Activate(pindex,bad));

    for(vector<uint160>::iterator it=hashes.begin(); it!= hashes.end(); it++){
	TrieNode *node = TrieEngine::Find(*it, m_root);
	if(node){
		CActInfo info(node);
		uint64_t limit = node->Limit();
    		if(limit != node->FutureLimit() && (pindex->nHeight - node->Age()) > MIN_LIMIT_TIME)
			info.limit = node->FutureLimit();
		balances.push_back(info);
	}else{
		balances.push_back(CActInfo());
	}
    }

    //Restore
    assert(Activate((*mapBlockIndex.find(oldHash)).second,bad));

    return true;
}

bool TrieView::Balance(uint160 key, uint64_t &balance){
    LOCK(cs_main);
    TrieNode *node = TrieEngine::Find(key, m_root);
    if(!node)
	return false;
    balance = node->Balance();
    return true;
}

bool TrieView::Limit(uint160 key, uint64_t &limit, uint64_t height){
    LOCK(cs_main);
    TrieNode *node = TrieEngine::Find(key, m_root);
    if(!node)
	return false;
    limit = node->Limit();
    if(limit != node->FutureLimit() && (height - node->Age()) > MIN_LIMIT_TIME)
	limit = node->FutureLimit();
    return true;
}


//Disregard any deposits in some region. Also include withdrawals from mempool
bool TrieView::ComplexBalances(int nMineConf, int nTheirsConf, vector<uint160> hashes, vector<CActInfo> &balances){
    LOCK(cs_main);

    assert(nMineConf <= nTheirsConf);

    //Get list of all tx information back to pindex
    vector<CBlock> blocks;
    CBlockIndex *phead = (*mapBlockIndex.find(m_bestBlock)).second;
    int runs = nTheirsConf-1;
    for(int i=0; i < runs; i++){
	CBlock block;
	if(!phead){
	    nMineConf--;
	    nTheirsConf--;
	    continue;
	}
    	assert(blockCache.ReadBlockFromDisk(block, phead)); 
	blocks.push_back(block);
	phead = phead->pprev;
    }


    for(vector<uint160>::iterator it=hashes.begin(); it!= hashes.end(); it++){
	TrieNode *node = TrieEngine::Find(*it, m_root);
	if(node){
	    uint64_t balance = node->Balance();
	    uint64_t deps=0;
	    uint64_t withdrawals=0;
	    uint64_t age=node->Age();
	    uint64_t limit=node->Limit();
	    uint64_t futurelimit=node->FutureLimit();
	    uint64_t ofst = nTheirsConf;
    	    if(limit != node->FutureLimit() && (chainActive.Height() - node->Age()) > (MIN_LIMIT_TIME+ofst))
		limit = node->FutureLimit();

	    //We want to remove effect of any txouts in the untrusted region, this could be optimized 
	    for(int i=0; i < (int)blocks.size(); i++){
		CBlock block=blocks[i];
		for(vector<CTransaction>::iterator it3=block.vtx.begin(); it3!=block.vtx.end(); it3++){
		    CTransaction tx = *it3;
		    for(vector<CTxOut>::iterator it4=tx.vout.begin(); it4!=tx.vout.end(); it4++){
			CTxOut txout = *it4;
			if(txout.pubKey == *it && (i<(nMineConf-1) || !pwalletMain->IsFromMe(tx))){
			    deps+=txout.nValue;
			    if(block.nHeight > age)
				age = block.nHeight;
			}
		    }
		}
	    }

	    //Include any withdrawals in mempool
	    vector<CTransaction> vtx;
	    mempool.lookup(*it,vtx);
	    for(vector<CTransaction>::iterator it2=vtx.begin(); it2!=vtx.end(); it2++){
		//printf("Found tx\n");
		CTransaction tx = *it2;
		if(!IsFinalTx(tx))
		    continue;
		for(vector<CTxIn>::iterator it3=tx.vin.begin(); it3!=tx.vin.end(); it3++){
		    CTxIn txin=*it3;
		    //printf("%s,%s %ld\n", txin.pubKey.GetHex().c_str(), it->GetHex().c_str(), txin.nValue);
		    if(txin.pubKey == *it){
			withdrawals+=txin.nValue;
			age = chainActive.Height() + 1;
		    }
		}
		for(vector<CTxOut>::iterator it3=tx.vout.begin(); it3!=tx.vout.end(); it3++){
		    CTxOut txout=*it3;
		    if(txout.pubKey == *it){
			if((pwalletMain->IsFromMe(tx) && nMineConf==0) || nTheirsConf==0)
			    balance+=txout.nValue;
		    }
		}
		if(tx.fSetLimit){
		   //TODO: there are cases where we can use an enlarged limit
		   //like if a queued update is old enough in chain it should switch
		   bool fTrusted = (pwalletMain->IsFromMe(tx) && nMineConf==0) || nTheirsConf==0; 
		   bool fSmaller = tx.nLimitValue < limit;
		   if(fTrusted || !fSmaller){
			futurelimit = tx.nLimitValue;
		   }
		}
	    }

	    if(deps + withdrawals > balance)
		balances.push_back(CActInfo());
	    else
	    	balances.push_back(CActInfo(balance-deps-withdrawals,age,limit,futurelimit));
	}else{
	    balances.push_back(CActInfo());
	}
    }

    return true;
}

uint64_t TrieView::CoinAge(uint160 pubkey){
    //Include any withdrawals in mempool
#if 0
    vector<CTransaction> vtx;
    mempool.lookup(pubkey,vtx);
    for(vector<CTransaction>::iterator it=vtx.begin(); it!=vtx.end(); it++){
	CTransaction tx = *it;
	if(!IsFinalTx(tx))
	    continue;
	for(vector<CTxIn>::iterator it2=tx.vin.begin(); it2!=tx.vin.end(); it2++){
	    CTxIn txin=*it2;
	    if(txin.pubKey == pubkey)
		return 0;
	}
	for(vector<CTxOut>::iterator it3=tx.vout.begin(); it3!=tx.vout.end(); it3++){
	    CTxOut txout=*it3;
	    if(txout.pubKey == pubkey)
		return 0;
	}
    }
#endif
    TrieNode* node = TrieEngine::Find(pubkey, m_root);
    assert(node);
    return chainActive.Height()-node->Age()+1;
}

//Disregard any deposits in some region. Also include withdrawals from mempool
bool TrieView::ConservativeBalances(int nMinConf, vector<uint160> hashes, vector<CActInfo> &balances){
    return ComplexBalances(nMinConf,nMinConf,hashes,balances);
}

uint32_t TrieView::GetSlice(uint256 block, uint160 left, uint160 right, uint8_t *buf, uint32_t sz, uint32_t *nodes){
    LOCK(cs_main);
    uint256 oldHash = m_bestBlock;

    //Blast from the past
    uint256 bad;
    if(!Activate(mapBlockIndex[block],bad)){
	return 0;
    }

//    m_root->Print();

    uint32_t pos=0;
    if(!TrieEngine::SubTrie(m_root,left,right,buf,&pos,(size_t)sz,nodes)){
        //Restore
        assert(Activate(mapBlockIndex[oldHash],bad));
	return 0;
    }

#if 0
    TrieNode *trie = TrieNode::Deserialize(buf,sz);
    trie->Print();
    delete trie;
#endif

    //Restore
    assert(Activate(mapBlockIndex[oldHash],bad));

    return pos;
}

bool TrieView::Flush(){
    LOCK(cs_main);
    LogPrintf("Writing file %s\n", m_bestBlock.GetHex().c_str());
    //TODO: this sucks. need to move to mmap asap
    boost::filesystem::path pathDebug = GetDataDir() / "trie.dat";
    FILE* fileout = fopen(pathDebug.string().c_str(), "wb");
    if(!fileout)
	return false;

    size_t fsize = m_root->Children() * 200; //TODO: define this as max size of trie node
    uint8_t *buf = (uint8_t*)malloc(fsize);
    uint32_t pos=0;
    uint32_t nodes=0;
    //m_root->Print();
    uint160_t left,right;
    left=0;
    memset(&right,0xFF,20);
    if(!TrieEngine::SubTrie(m_root,left,right,buf,&pos,fsize,&nodes)){
	free(buf);
     	fclose(fileout);
	return false;
    }

    LogPrintf("Serialized: %d bytes\n", pos);
    fwrite(&m_bestBlock,32,1,fileout);
    fwrite(&pos,4,1,fileout);
    fwrite(buf,pos,1,fileout);
    fclose(fileout);
    free(buf);
    return true;
}
