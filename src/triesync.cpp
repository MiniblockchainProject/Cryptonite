// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "txdb.h"
#include "init.h"
#include "wallet.h"	

TrieSync::TrieSync(){
    log2size=0;
}

#define DEC_LOG2SIZE() (log2size = (log2size <= 0) ? 0 : (log2size-1))
#define INC_LOG2SIZE() (log2size = (log2size >= 158) ? 158 : (log2size+1))

CBlockIndex* TrieSync::GetSyncPoint(){
    AssertLockHeld(cs_main);

   //TODO: is initial download doesn't really work
    if(fLoading || IsInitialBlockDownload())
	return 0;

    //we operate only on chainHeaders because block validation is not possible
    //until trie comes online. therefore chainActive doesn't even exist

    CBlockIndex *pindex = chainHeaders.Tip();
    uint64_t count=0;
    while(pindex){
  	//Use a small fudge factor because intense reorg at the tip can cause failure
	if(!(pindex->nStatus & BLOCK_HAVE_DATA) && pindex->nHeight + 5 < chainHeaders.Height())
	    break;
	count++;
	if(count > MIN_HISTORY)
	    break;
	pindex = pindex->pprev;
    }

    if(count >= MIN_HISTORY)
	return pindex;
    return 0;
}

bool TrieSync::CanSync(){
    LOCK(cs_main);


    return GetSyncPoint();
}

void TrieSync::Reset(){
    LOCK(cs_main);
    BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slices){
	delete pair.second;
    }
    BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slicesRequested){
	delete pair.second;
    }
    slices.clear();
    slicesRequested.clear();
    log2size = 0;
}

//Remove any slices which are no longer tennable
void TrieSync::Update(){
    LOCK(cs_main);
    BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slices){
	if(chainHeaders.Contains(pair.first) && (chainHeaders.Height() - pair.first->nHeight) >= (int64_t)MIN_HISTORY){
   	    //Slices are also no good if any tx data is missing between them and tip
    	    CBlockIndex *pindex = chainHeaders.Tip();
	    int cnt=0;
	    for(int i=pair.first->nHeight; i < pair.first->nHeight + MIN_HISTORY; i++){
	     	if(!(chainHeaders[i]->nStatus & BLOCK_HAVE_DATA)){
		    delete pair.second;
		    slices.erase(pair.first);		
	    	    continue;
		}
	    }
	    continue;
	}
	
	delete pair.second;
	slices.erase(pair.first);		
    }
}

void TrieSync::AbortSlice(CSlice slice, bool tooBig, set<NodeId> cnodes, NodeId id){
    //This little piece of magic is the Who be frontin' algorithm

    LOCK(cs_main);
    RemoveRequest(slice);

    if(!tooBig){
	bans.insert(id);
	return;
    }

    //as discussed in main.cpp, blindly increasing size is a bad idea!
    if(!nodesTooBig.count(id)){
	//log2size++;
	INC_LOG2SIZE();
	nodesTooBig.insert(id);
	return;
    }

    //See if all of cnodes is in nodestoobig
    bool notfound=false;
    BOOST_FOREACH(NodeId tid, cnodes){
	if(!nodesTooBig.count(tid)){
	    notfound=true;
	    break;
	}
    }

    if(notfound){
	bans.insert(id);
    }else{
	bans.clear();
	nodesTooBig.clear();
	//log2size++;
	INC_LOG2SIZE();
    }
}

CBlockIndex* TrieSync::RemoveRequest(CSlice slice){
    CBlockIndex *pindex=0;
    for(multimap<CBlockIndex*,CSlice*>::iterator it=slicesRequested.begin(); it!=slicesRequested.end(); it++){
	pair<CBlockIndex*,CSlice*> pair=*it;
	CSlice tslice = *pair.second;
	if(tslice.m_block == slice.m_block &&
	         tslice.m_left == slice.m_left &&
	         tslice.m_right == slice.m_right){
	   delete it->second;
	   pindex = it->first;
	   slicesRequested.erase(it);
	   break;
	}
    }
    return pindex;
}

bool TrieSync::AcceptSlice(CSlice slice){
    LOCK(cs_main);

    CBlockIndex* pindex = RemoveRequest(slice);

    if(slice.m_data.size()>MAX_TRIE_SLICE_SIZE)
	return false;
    TrieNode *root;
    root = TrieNode::Deserialize(&slice.m_data[0],MAX_TRIE_SLICE_SIZE);
    if(!root){	
	printf("Slice not materialize\n");
	return false;
    }
    //Verify the hash
    if(root->Hash() != mapBlockIndex[slice.m_block]->hashAccountRoot){	
	printf("Slice not hash\n");
	delete root;
	return false;
    }

    bool valid = TrieEngine::Prove(root,slice.m_left,slice.m_right);
    delete root;
    if(!valid)
	printf("Slice not prove\n");
 
    if(valid && pindex){
	slices.insert(pair<CBlockIndex*,CSlice*>(pindex,new CSlice(slice)));	
    }   
	DEC_LOG2SIZE();
    return valid;
}

class CInterval {
public:
    CInterval(uint160 lin, uint160 rin){
	left=lin; right=rin;
    }
    uint160 left,right;
};

int TrieSync::GetProgress(){
    list<CInterval> intervals;
    GetIntervals(slices,intervals); 

    uint160 total=0;
    BOOST_FOREACH(CInterval i, intervals){
	total += i.right - i.left;
    }

    total = total >> 152;
    return (int)total.GetLow64();
}

bool compareIntervals(CInterval lhs, CInterval rhs) { 
    return lhs.left < rhs.left; }


uint160 INC_UINT160(uint160 x){
    uint160 max;
    memset(&max,0xFF,20);
    if(x == max)
        return max;
    return x+1;
}

bool overlap_left(list<CInterval>::iterator it, list<CInterval>::iterator it2){
	return (it2->left <= INC_UINT160(it->right) && (it2->left) >= it->left);
}

bool overlap(list<CInterval>::iterator it, list<CInterval>::iterator it2){
	return (overlap_left(it,it2) || overlap_left(it2,it));
}




void TrieSync::GetIntervals(multimap<CBlockIndex*,CSlice*> &slices, list<CInterval> &intervals){
   //We want to produce a vector of all intervals that either have requests outstanding
    //or have already been fetched

    int k=0;
    BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slices){
	CSlice *pslice = pair.second;
	intervals.push_back(CInterval(pslice->m_left,pslice->m_right));
	printf("__INTERVAL%d:  %s - %s\n",k ,pslice->m_left.GetHex().c_str() ,pslice->m_right.GetHex().c_str());
	k++;
    }

    //printf("IS: %ld\n", intervals.size());

    //This is horrible slow. n^3?
    bool progress=true;
    while(progress){
	progress=false;
	for(list<CInterval>::iterator it=intervals.begin(); it!=intervals.end(); it++){
	    list<CInterval>::iterator it2=it;
	    for(it2++; it2!=intervals.end(); it2++){
		if(overlap(it,it2)){
		    if(it2->right > it->right)
		    	it->right = it2->right;
		    if(it2->left < it->left)
                        it->left = it2->left;
		    intervals.erase(it2);
		    progress=true;
		    break;
		}
	    }
	    if(progress)
		break;
	}
    }	


     k=0;
    BOOST_FOREACH(CInterval i, intervals){
        printf("INTERVAL%d:  %s - %s\n",k ,i.left.GetHex().c_str() ,i.right.GetHex().c_str());
	k++;
    }

}

CSlice TrieSync::GetSlice(NodeId id){
    LOCK(cs_main);

    if(bans.count(id))
	return CSlice(0);


    //This is some crazy ass algorithm
    multimap<CBlockIndex*,CSlice*> allSlices;
    allSlices.insert(slices.begin(),slices.end());
    allSlices.insert(slicesRequested.begin(),slicesRequested.end());	
    list<CInterval> intervals;
 printf("SLICE SIZE SHIFT %d %d\n", log2size, (159 - log2size));
    GetIntervals(allSlices,intervals);
 
    //printf("IS2: %ld\n", intervals.size());


    //So now intervals are compacts into smallest set. We like order. so order fracking things
    intervals.sort(compareIntervals);
    uint160 lowest=0;
    uint160 right=0;
    memset(&right,0xFF,20);
    if((*intervals.begin()).right == right && (*intervals.begin()).left == lowest)
	return CSlice(0);

    if(intervals.size()){
	if((*intervals.begin()).left != 0){
	    right = (*intervals.begin()).left - 1;
	}else{
	    lowest = (*intervals.begin()).right + 1;
    	    if(intervals.size() > 1)
	        right = (*(intervals.begin()++)).left - 1;
	}
    }

    //Make sure the slice is not too large
    while(right-lowest > ((uint160)1 << (159 - log2size)))
	right = lowest + ((right - lowest) >> 1);

    if(right <= lowest){
	return CSlice((uint256)0);
    }
    //TODO: totally not safe for short tries
    CSlice *ret = new CSlice(chainHeaders[chainHeaders.Height()-MIN_HISTORY]->GetBlockHash());
    ret->m_left = lowest;
    ret->m_right = right;
    slicesRequested.insert(pair<CBlockIndex*,CSlice*>(chainHeaders[chainHeaders.Height()-MIN_HISTORY],ret));
    return *ret;
}

bool TrieSync::ReadyToBuild(){
    LOCK(cs_main);
    Update(); //Make sure crud is gone
    if(!CanSync()){
	printf("Something really wrong\n");
	return false; //Something really wrong
    }

    //Make sure left alignment is good enough
    uint160 left_required = 0;
    bool progress=true;
    while(progress){
 	progress=false;
    	BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slices){
	    CSlice *pslice = pair.second;
	    if(pslice->m_left <= (left_required + 1) && pslice->m_right > left_required){
		left_required = pslice->m_right;
		progress = true;
		break;
	    }
    	}
    }

    uint160 right_max;
    memset(&right_max,0xFF,20); //Set to -1    

    if(left_required != right_max){
	printf("Not enough %s %ld %ld\n", left_required.GetHex().c_str(), slices.size(), slicesRequested.size());
	return false;
    }

    //Against all odds, she is ready to roll!
    printf("Ready to build\n");
    return true;
}

//TODO: all wrong
void TrieSync::ApplyTransactions(map<uint160, AccountData> &data, CBlock &block){
    //Txout first
    BOOST_FOREACH(CTransaction tx, block.vtx){
	BOOST_FOREACH(CTxOut txout, tx.vout){   
	    AccountData ad; 
	    if(data.find(txout.pubKey)!=data.end())
		ad = data[txout.pubKey];
  	    ad.SetKey(txout.pubKey);	
	    //No set age on output
//	    ad.SetAge(block.nHeight);
	    ad.SetBalance(ad.Balance()+txout.nValue);
	    data[txout.pubKey] = ad;
	}
    }

    BOOST_FOREACH(CTransaction tx, block.vtx){
	BOOST_FOREACH(CTxIn txin, tx.vin){   
	    if(data.find(txin.pubKey)==data.end())
		continue; //Account not in slices yet, no worries
	    AccountData ad = data[txin.pubKey]; 

	    if(txin.nValue >= ad.Balance()){
		data.erase(txin.pubKey);
		continue;
	    }
	    if(tx.fSetLimit)
		ad.SetFutureLimit(tx.nLimitValue);

	    if(ad.FutureLimit() < ad.Limit())
		ad.SetLimit(ad.FutureLimit());

	    if(block.nHeight - ad.Age() > MIN_LIMIT_TIME){
 	        ad.SetLimit(ad.FutureLimit());		
	    }
	    ad.SetAge(block.nHeight);
	    
	    ad.SetBalance(ad.Balance()-txin.nValue);
	    data[txin.pubKey] = ad;
	}
    }
}

bool compareCSlice(pair<CBlockIndex*,CSlice*> lhs, pair<CBlockIndex*,CSlice*> rhs) { 
    return lhs.second->nHeight < rhs.second->nHeight; }

TrieNode* TrieSync::Build(uint256 &block){
    vector<pair<CBlockIndex*,CSlice*> > slicev;
    slicev.insert(slicev.begin(),slices.begin(),slices.end());

    //Must sort the slices oldest to newest
    sort(slicev.begin(), slicev.end(),compareCSlice);

    uint64_t last_height = 0;
    map<uint160, AccountData> data;
    BOOST_FOREACH(PAIRTYPE(CBlockIndex*,CSlice*) pair, slicev){
	CSlice *slice=pair.second;
	if(last_height != 0){
	    for(uint64_t nHeight=last_height; nHeight <= (uint64_t)pair.first->nHeight; nHeight++){
		CBlock block;
		blockCache.ReadBlockFromDisk(block,pair.first);
		ApplyTransactions(data,block);
	    }
	}
	TrieNode *trie = TrieNode::Deserialize(&slice->m_data[0],slice->m_data.size());
	assert(trie);
	
	list<TrieNode*> leaves;
	trie->FindAll(NODE_LEAF,&leaves);

	//If a newer slice has a dup entry it doesn't matter. Just overwrite
	BOOST_FOREACH(TrieNode* leaf, leaves){
	    data[leaf->Key()] = *leaf;
	}
	delete trie;
	last_height=pair.first->nHeight+1;//Only wind tx's after this blocks index
	block = pair.first->GetBlockHash();
    }

    //List ready for construction
    TrieNode* root=0;
    BOOST_FOREACH(PAIRTYPE(uint160,AccountData) pair, data){
	AccountData ad=pair.second;
	TrieNode *node = new TrieNode(NODE_LEAF);
	*((AccountData*)node) = ad;
	TrieEngine::Insert(&root,node);	
    }
    return root;
}

