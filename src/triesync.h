// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRIESYNC_H
#define TRIESYNC_H

class CInterval;

class TrieSync {
public:
    TrieSync();

    CBlockIndex *GetSyncPoint();
    bool CanSync();
    void Update();
    bool ReadyToBuild();
    TrieNode* Build(uint256 &block);
    void ApplyTransactions(map<uint160, AccountData> &data, CBlock &block);
    CSlice GetSlice(NodeId id);
    void AbortSlice(CSlice slice, bool tooBig,set<NodeId>, NodeId);
    bool AcceptSlice(CSlice slice);
    void Reset();
    int GetProgress();
    void GetIntervals(multimap<CBlockIndex*,CSlice*> &slices, list<CInterval> &intervals);
    CBlockIndex* RemoveRequest(CSlice slice);

    uint32_t log2size=0;
    multimap<CBlockIndex*,CSlice*> slicesRequested;
    multimap<CBlockIndex*,CSlice*> slices;

    set<NodeId> bans;
    set<NodeId> nodesTooBig;
};

#endif //TRIESYNC_H
