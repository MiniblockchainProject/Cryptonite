#ifdef JPC_H

typedef struct {
    // header
    int nVersion;
    uint256 hashPrevBlock;
    uint256 hashActMerkleRoot;
    uint256 hashTxMerkleRoot;
    uint64_t nAccounts; //Also store number of sheet items so that new clients can query blocks
    uint32_t nTime;
    uint32_t nBits;
    uint64_t nNonce; //Use 64bit nonce for now so that unique root's are not required for entropy
} jpcblock_t;



#endif //JPC_H
