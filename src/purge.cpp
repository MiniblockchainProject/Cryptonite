// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "init.h"
#include "txdb.h"
#include "util.h"

#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>
#include <boost/interprocess/sync/file_lock.hpp>

using namespace std;

void PurgeDB(){
    CValidationState state;
    set<int> setNeed;
    set<CBlockIndex*> setDelete;

    boost::filesystem::path pathLockFile = GetDataDir() / ".lock";
    boost::filesystem::path pathBlocks = GetDataDir() / "blocks";
    boost::filesystem::directory_iterator end;

    boost::interprocess::file_lock lock(pathLockFile.string().c_str());
    if (!lock.try_lock()){
        printf("Cannot obtain a lock on data directory. Cryptonite Core is probably already running.\n");
	goto fail;
    }

    printf("Are you sure you want to purge?!!!!\n");
    //TODO: check answer

    //Load everything up
    printf("Loading databases\n");
    fLoading=true;
    pblocktree = new CBlockTreeDB(1<<21, false, fReindex);
    pviewTip = new TrieView();

    if (!LoadBlockIndex()) {
         printf("Error loading block database");
         goto fail;
    }

    if (!ActivateBestChain(state)){
	printf("Could not activate best chain\n");
        goto fail;
    }

    printf("Tip is block %ld\n", chainActive.Height());
    if(chainActive.Height() <= MIN_HISTORY){
	printf("Not enough history to prune\n");
	goto fail;
    }

    //First pass, locate all blocks that are still actually in view and add those
    //block and undo files to undeletable

    //mapBlockIndex contains all blocks, so we can read those for info
    BOOST_FOREACH(PAIRTYPE(uint256, CBlockIndex*) item, mapBlockIndex){
	CBlockIndex *pindex = item.second;	
	if(pindex->nHeight + MIN_HISTORY >= chainActive.Height()){
	    //Block cannot be deleted
	    if (pindex->nStatus & BLOCK_HAVE_DATA || pindex->nStatus & BLOCK_HAVE_UNDO)
		setNeed.insert(pindex->nFile);
        }
    }

    //Second pass, locate all blocks that can have transactions deleted from txindex
    BOOST_FOREACH(PAIRTYPE(uint256, CBlockIndex*) item, mapBlockIndex){
	CBlockIndex *pindex = item.second;	
	if(pindex->nHeight + MIN_HISTORY < chainActive.Height()){
	    //Block can be deleted
	    if (pindex->nStatus & BLOCK_HAVE_DATA || pindex->nStatus & BLOCK_HAVE_UNDO)
		//Block has TX's
		if(!setNeed.count(pindex->nFile)) //Don't need file
		    setDelete.insert(pindex);
        }
    }

    //Third pass, delete tx's from txindex
    BOOST_FOREACH(CBlockIndex* pindex, setDelete){
	CBlock block;
	blockCache.ReadBlockFromDisk(block, pindex);
	BOOST_FOREACH(CTransaction tx, block.vtx){
	     pblocktree->EraseTxIndex(tx.GetTxID());
	}
	pindex->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
	pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
    }

    //Final operation, delete blk and rev files which are unneeded
    if (!exists(pathBlocks)){
	printf("Could not open blocks directory\n");
	goto fail;
    }

    //Actually delete the files
    for( boost::filesystem::directory_iterator iter(pathBlocks) ; iter != end ; ++iter ) {
             string fname = iter->path().filename().generic_string(); 
	     if(fname.size() != 12)
		continue;
	     if(fname.compare(0, 3, "rev") && fname.compare(0,3,"blk"))
		continue;
	     
	     int idx=0;
	     if(sscanf(fname.c_str()+3,"%d.dat",&idx)!=1)
		continue;

	     if(setNeed.count(idx))
		continue;

	     remove(iter->path());
     }

fail :
    lock.unlock();
    exit(0);
}
