// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "main.h"
#include "txdb.h"
#include "init.h"

#define CACHE_SIZE MIN_HISTORY

CCriticalSection cs_block;

class CBlockCrud {
public:
    CBlockCrud(CBlockUndo u, uint256 h){
	undo = u; hash = h;
    }
    CBlockUndo undo;
    uint256 hash;
};

static list<CBlockCrud> listUndo;
static map<uint256,list<CBlockCrud>::iterator> mapUndo;

static list<CBlock> listBlock;
static map<uint256,list<CBlock>::iterator> mapBlock;

bool CBlockCache::WriteUndoToDisk(CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo){
    LOCK(cs_block);

    // Open history file to append
    CAutoFile fileout = CAutoFile(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("CBlockUndo::WriteToDisk : OpenUndoFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(undo);
    fileout << FLATDATA(Params().MessageStart()) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout);
    //printf("Writing at %ld\n", fileOutPos);
    if (fileOutPos < 0)
        return error("CBlockUndo::WriteToDisk : ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << undo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << undo;
    fileout << hasher.GetHash();

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload())
        FileCommit(fileout);

    //Update the cached copy if present
    map<uint256,list<CBlockCrud>::iterator>::iterator it = mapUndo.find(hashBlock);
    if(it != mapUndo.end()){
	(*(it->second)).undo = undo;
    }


    return true;
}

bool CBlockCache::ReadUndoFromDisk(const CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo){
    LOCK(cs_block);

    map<uint256,list<CBlockCrud>::iterator>::iterator it = mapUndo.find(hashBlock);
    if(it != mapUndo.end()){
	CBlockCrud crud = *(it->second);
	undo = crud.undo;
	//Move list element to front
	listUndo.erase(it->second);
	listUndo.push_front(crud);
	mapUndo[hashBlock] = listUndo.begin();

	return true;
    }

    if(!ReadUndoFromDiskI(pos,hashBlock,undo))
	return false;

    //Gotta trim it up. This is rough
    if(listUndo.size() >= CACHE_SIZE){
	CBlockCrud back = listUndo.back();
	uint256 hashBack = back.hash;
	listUndo.pop_back();
	mapUndo.erase(hashBack);
    }

    //Insert into front
    listUndo.push_front(CBlockCrud(undo,hashBlock));
    mapUndo[hashBlock] = listUndo.begin();

    return true;
}

bool CBlockCache::ReadUndoFromDiskI(const CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo){
    // Open history file to read
    CAutoFile filein = CAutoFile(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("CBlockUndo::ReadFromDisk : OpenBlockFile failed");

    // Read block
    uint256 hashChecksum;
    try {
        filein >> undo;
        filein >> hashChecksum;
    }
    catch (std::exception &e) {
        return error("%s : Deserialize or I/O error - %s", __PRETTY_FUNCTION__, e.what());
    }

    // Verify checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << undo;
    if (hashChecksum != hasher.GetHash())
        return error("CBlockUndo::ReadFromDisk : Checksum mismatch");

    return true;
}

bool CBlockCache::ReadBlockFromDiskI(CBlock& block, const CDiskBlockPos& pos)
{
    LOCK(cs_block);

    block.SetNull();

    // Open history file to read
    CAutoFile filein = CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (!filein)
        return error("ReadBlockFromDisk : OpenBlockFile failed");

    // Read block
    try {
        filein >> block;
    }
    catch (std::exception &e) {
        return error("%s : Deserialize or I/O error - %s", __PRETTY_FUNCTION__, e.what());
    }
    return true;
}

bool CBlockCache::ReadTxFromDisk(CTransaction& tx, const CDiskTxPos &disktx){
    LOCK(cs_block);

    //Need blockindex to be able to find tx ?
    CBlockIndex *pindex= mapBlockIndex[disktx.hashBlock];
    CBlock block;
    if(!ReadBlockFromDisk(block,pindex))
	return false;
    tx = block.vtx[disktx.nTxOffset];
    return true;
}


bool CBlockCache::ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex)
{
    LOCK(cs_block);
    static int cnt=0;

    map<uint256,list<CBlock>::iterator>::iterator it = mapBlock.find(pindex->GetBlockHash());
    if(it != mapBlock.end()){
	block = *(it->second);
	//Move list element to front
	listBlock.erase(it->second);
	listBlock.push_front(block);
	mapBlock[pindex->GetBlockHash()] = listBlock.begin();
	//printf("Hit\n");
	//if(cnt++ == 200)
	//    assert(0);
	return true;
    }

    if (!ReadBlockFromDiskI(block, pindex->GetBlockPos())){
	LogPrintf("ReadBlockFromDisk: Could not find block %s\n", pindex->GetBlockHash().GetHex().c_str());
	//assert(0);
        return false;
    }
    uint256 hash = block.GetHash();
    if (hash != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*) : GetHash() doesn't match index");

    //Gotta trim it up. This is rough
    if(listBlock.size() >= CACHE_SIZE){
	CBlock back = listBlock.back();
	uint256 hashBack = back.GetHash();
	listBlock.pop_back();
	mapBlock.erase(hashBack);
	//printf("Evict\n");
    }

    //Insert into front
    listBlock.push_front(block);
    mapBlock[hash] = listBlock.begin();
    //printf("Add to cache\n");
    return true;
}

bool CBlockCache::WriteBlockToDisk(CBlock& block, CDiskBlockPos& pos)
{
    LOCK(cs_block);
    // Open history file to append
    CAutoFile fileout = CAutoFile(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (!fileout)
        return error("WriteBlockToDisk : OpenBlockFile failed");

    // Write index header
    unsigned int nSize = fileout.GetSerializeSize(block);
    fileout << FLATDATA(Params().MessageStart()) << nSize;

    // Write block
    long fileOutPos = ftell(fileout);
    if (fileOutPos < 0)
        return error("WriteBlockToDisk : ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    // Flush stdio buffers and commit to disk before returning
    fflush(fileout);
    if (!IsInitialBlockDownload())
        FileCommit(fileout);

    //Update the cached copy if present
    map<uint256,list<CBlock>::iterator>::iterator it = mapBlock.find(block.GetHash());
    if(it != mapBlock.end()){
	*(it->second) = block;
    }

    return true;
}


