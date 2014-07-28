// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BLOCKCACHE_H
#define BLOCKCACHE_H

class CDiskBlockPos;
class CDiskTxPos;
class CBlockUndo;

class CBlockCache {
public:
    bool WriteUndoToDisk(CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo);
    bool ReadUndoFromDisk(const CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo);
    bool ReadUndoFromDiskI(const CDiskBlockPos &pos, const uint256 &hashBlock, CBlockUndo &undo);

    bool ReadTxFromDisk(CTransaction& tx, const CDiskTxPos &disktx);
    bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex);
    bool WriteBlockToDisk(CBlock& block, CDiskBlockPos& pos);
    bool ReadBlockFromDiskI(CBlock& block, const CDiskBlockPos& pos);

};

#endif //BLOCKCACHE_H
