// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef TRIE_H
#define TRIE_H

#include <list>

using namespace std;

#define NODE_LEAF   1
#define NODE_BRANCH 2
#define NODE_HASH   3

typedef uint256 uint256_t;
typedef uint160 uint160_t;

class AccountData {
public:
	AccountData();
	virtual ~AccountData() {}
	virtual void SetKey(uint160_t key){m_key = key; Dirtify(); }
	uint160_t Key(){ return m_key; }
	virtual uint256_t Hash();
	virtual bool Serialize(uint8_t *dst, uint32_t *pos, uint32_t max);
	uint64_t Age() { return m_age; }
	void SetAge(uint64_t age) { m_age = age; Dirtify();}
	void SetBalance(uint64_t balance) { m_balance = balance; Dirtify(); }
	void SetLimit(uint64_t limit) { m_limit = limit; Dirtify(); }
	void SetFutureLimit(uint64_t limit) { m_futurelimit = limit; Dirtify(); }
	uint64_t Balance() { return m_balance; }
	uint64_t Limit() { return m_limit; }
	uint64_t FutureLimit() { return m_futurelimit; }
	virtual void Dirtify() {};
protected:
	virtual uint32_t DeserializeI(uint8_t *src, uint32_t sz);
	//Just for caching
	uint32_t m_modified;
	uint256_t m_hash;

	uint64_t m_align;
	//----------------Begin Packed Struct------------------
	uint64_t m_age;  //8
	uint64_t m_balance; //8
	uint64_t m_limit; //8
	uint64_t m_futurelimit; //8
	uint160_t m_key; //32 
	uint8_t m_struct_end;
	//----------------End Packed Struct--------------------
};

class TrieNode : public AccountData {
public:
	TrieNode(uint32_t type);
	~TrieNode();
	void Print(uint32_t level=0, uint32_t bits=0);
	void SetKey(uint160_t key){m_key = key; Dirtify(); }
	uint64_t Children() { return m_children; }
	uint32_t Type() { return m_type; }
	TrieNode *Parent() { return m_parent; }
	void Add(TrieNode*);
	TrieNode* Remove(TrieNode*);
	void SetBits(uint32_t bits) { m_key_bits = bits; Dirtify(); }
	uint32_t Bits() { return m_key_bits; }
	void Replace(TrieNode* where, TrieNode* What);
	void SetParent(TrieNode *parent) { m_parent = parent; }
	uint32_t GetTotalBits();
	void Dirtify();
	void Subtract(uint64_t);
	void Add(uint64_t);
	uint256_t Hash();
	bool Serialize(uint8_t *dst, uint32_t *pos, uint32_t max);
	static TrieNode* Deserialize(uint8_t *src, uint32_t sz);
	void Parentify(TrieNode* parent);
	uint64_t FindChildren();
	void FindAll(uint32_t type, list<TrieNode*> *ret);
	uint160_t GetTotalKey(TrieNode* child, uint160_t key);
	TrieNode *m_left, *m_right;
protected:
	uint32_t DeserializeI(uint8_t *src, uint32_t sz);
private:
	uint32_t m_type;
	uint64_t m_children;

	uint32_t m_key_bits;

	TrieNode *m_parent;
};

class TrieEngine {
public:
	static void Insert(TrieNode **root, TrieNode *node, uint32_t bits=0);
	static void Remove(TrieNode **root, TrieNode *node);
	static uint64_t Size(TrieNode *root);
	static bool SubTrie(TrieNode *root, uint160_t left, uint160_t right, uint8_t *dst, uint32_t *pos, uint32_t max, uint32_t *nodes, uint160_t ckey=0, uint32_t bits=0, bool hashOnly=false);
	static void RebuildStructure(TrieNode *root);
	static bool Prove(TrieNode *root, uint160_t left, uint160_t right);
	static TrieNode* Find(uint160_t key, TrieNode *root, uint32_t keybits=0);
	static void TraverseLeft(TrieNode *leftnode, uint160_t left, uint160_t right, list<TrieNode*> *lefts, int bits);
	static void TraverseRight(TrieNode *rightnode, uint160_t left, uint160_t right, list<TrieNode*> *rights, int bits);
};

void SerializeHash(uint8_t *dst, uint32_t *pos, uint160_t hash);
void DeserializeHash(uint160_t *hash, uint8_t *src);
void SerializeHash(uint8_t *dst, uint32_t *pos, uint256_t hash);
void DeserializeHash(uint256_t *hash, uint8_t *src);

#endif //TRIE_H
