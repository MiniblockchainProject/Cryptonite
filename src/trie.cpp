// Copyright (c) 2014 The Mini-Blockchain Project
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <iostream>
#include <vector>
#include <algorithm>

#include "uint256.h"
#include "hash.h"
#include "trie.h"

///////////////////Copied from core for testing
//#define DEBUG_TRIE
#ifndef DEBUG_TRIE
uint160 GetRandHash();
#else
#define UINT64_MAX ((uint64_t)-1LL)
uint160 GetRandHash()
{
    uint160 hash;
    uint32_t i;
	for(i=0; i < sizeof(hash); i++){
		((unsigned char*)&hash)[i] = rand();
	}	
//    RAND_bytes((unsigned char*)&hash, sizeof(hash));
    return hash;
}
#endif
///////////////////////////////////////////

using namespace std;


AccountData::AccountData(){
	m_key=0;
	m_balance=0;
	m_limit=UINT64_MAX;
	m_futurelimit=UINT64_MAX;
	m_age=0;
	m_hash=0;
	m_modified=1;
}

uint256_t AccountData::Hash(){
	if(!m_modified)
		return m_hash;
	m_modified=false;
	return m_hash = ::Hash((uint8_t*)&m_age,&m_struct_end);
}

bool AccountData::Serialize(uint8_t *dst, uint32_t *pos, uint32_t max){
	uint32_t sz = (uint8_t*)&m_struct_end - (uint8_t*)&m_age;
	if(max - *pos < sz)
		return false;
	memcpy(dst+*pos,&m_age,sz);
	(*pos)+=sz;
	return true;
}

uint32_t AccountData::DeserializeI(uint8_t *src, uint32_t sz){
	uint32_t msz = (uint8_t*)&m_struct_end - (uint8_t*)&m_age;
	//printf("%d %d\n", sz, msz);
	if(sz < msz){
		printf("Fail act %d\n", sz);
		return 0;
	}
	memcpy(&m_age,src,msz);
	return msz;
}

//Constructor
TrieNode::TrieNode(uint32_t type){
	m_type = type;
	m_children = 0;
	if(type == NODE_LEAF)
		m_children=1;
	m_modified = 1;
	m_key_bits = 0;
	m_key = 0;
	m_left = 0;
	m_right = 0;
	m_parent = 0;
}

//Destructor
TrieNode::~TrieNode(){
//this is really dangerous because of reparenting
	if(m_left)
		delete m_left;
	if(m_right)
		delete m_right;
}

//Print the tree for debugging
void pad(uint32_t level){
	uint32_t i;
	for(i=0; i < level; i++){
		printf(" ");
	}
}

//Prints a byte in a binary with optional bit locator bars
char* itoa2(char* buf, unsigned int val, int line, int line2){
	
	buf[11] = 0;
	int i,o=0;
	
	for(i=0; i < 8; i++, val <<= 1){
		if(i==line)
			buf[i+o++] = '|';
		else if(i==line2)
			buf[i+o++] = '|';
		buf[i+o] = "01"[(val >> 7) & 1];
	}
	buf[i+o]=0;
	return buf;
	
}

void print_key(uint160_t key, int start, int length){
	int sz = key.GetSerializeSize(0,0);
	int ofst=0;
	unsigned char *pn = key.begin();
        char psz[sz*8 + 1];
	char bin[32];
        for (int i = 0; i < sz; i++){
            ofst += sprintf(psz +ofst, "%s",  itoa2(bin,((unsigned char*)pn)[sz - i - 1],start-i*8,start+length-i*8));
	}
        cout << std::string(psz, psz + ofst) << "\n";
}

void TrieNode::Print(uint32_t level, uint32_t bits){
	pad(level); printf("{\n");
	pad(level); printf(" Type: ");
	switch(m_type){
		case NODE_LEAF: printf("Leaf\n"); break;
		case NODE_BRANCH: printf("Branch\n"); break;
		case NODE_HASH: printf("Hash\n"); break;
	}
	if(m_type==NODE_BRANCH){
		pad(level); printf(" Bits: %d\n", m_key_bits);
		pad(level); cout << " Key: "; print_key(GetTotalKey(m_left,0),bits,m_key_bits);//GetTotalKey(m_right,0),bits,m_key_bits);
	}else if(m_type==NODE_HASH){
		pad(level); cout << " Hash: " << m_hash.GetHex() << "\n";
	}else{
		pad(level); cout << " Key: " << m_key.GetHex() << "\n";
		pad(level); cout << " Balance: " << m_balance << "\n";
		pad(level); cout << " Age: " << m_age << "\n";
	}
	if(m_left)
		m_left->Print(level+1,bits+m_key_bits+1);
	if(m_right)
		m_right->Print(level+1,bits+m_key_bits+1);
	pad(level); printf("}\n");
}

//Mark this node and all parents as dirty
void TrieNode::Dirtify(){
	m_modified = 1;

	//Update dirty flags
	TrieNode *parent = m_parent;
	while(parent){
		parent->m_modified = 1;
		parent = parent->m_parent;
	}
}

//Add a node
void TrieNode::Add(TrieNode *node){
	node->m_parent = this;
	assert(m_left==0 || m_right==0);
	Dirtify();

	//Add the new nodes child count up the tree
	m_children += node->m_children;
	TrieNode *parent = m_parent;
	while(parent){
		parent->m_children += node->m_children;
		parent = parent->m_parent;
	}

	if(m_left==0){
		m_left = node;
		return;
	}
	m_right = node;
}

//Subtract from all child counts
void TrieNode::Subtract(uint64_t count){
	m_children -= count;
	TrieNode* parent = m_parent;
	while(parent){
		parent->m_children -= count;
		parent = parent->m_parent;
	}
}

//Add to all child counts
void TrieNode::Add(uint64_t count){
	m_children += count;
	TrieNode* parent = m_parent;
	while(parent){
		parent->m_children += count;
		parent = parent->m_parent;
	}
}

//Remove a node
TrieNode* TrieNode::Remove(TrieNode *node){
	m_modified = 1;

	Dirtify();

	if(m_left==node){
		Subtract(m_left->m_children);
		m_left=0;
		return m_right;
	}
	assert(m_right);
	Subtract(m_right->m_children);
	m_right=0;
	return m_left;
}

//Replace a node
void TrieNode::Replace(TrieNode* where, TrieNode* what){
	m_modified = 1;
	Subtract(where->m_children);
	Add(what->m_children);

	Dirtify();

	what->m_parent = this;
	if(m_left==where){
		m_left=what;
		return;
	}
	assert(m_right==where);
	m_right=what;
}

uint32_t TrieNode::GetTotalBits(){
	return m_key_bits + 1 + ((m_parent!=NULL)?m_parent->GetTotalBits():0);
}

uint256_t TrieNode::Hash(){
	if(m_type==NODE_LEAF)
		return AccountData::Hash();
	if(m_type==NODE_HASH)
		return m_hash;
	//Then this is a branch node
	if(!m_modified)
		return m_hash;
	m_modified=false;

	//need to hash key, key_bits, left hash and right hash
	uint256_t left = m_left->Hash();
	uint256_t right = m_right->Hash();
	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, &m_key, sizeof(m_key));	
	SHA256_Update(&ctx, &m_key_bits, sizeof(m_key_bits));
	SHA256_Update(&ctx, &left, sizeof(left));
	SHA256_Update(&ctx, &right, sizeof(right));

	uint256_t hash1;
	SHA256_Final((unsigned char*)&hash1, &ctx);
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&m_hash);
	
	return m_hash;
}

//Serialize
bool TrieNode::Serialize(uint8_t *dst, uint32_t *pos, uint32_t max){
	if(m_type==NODE_LEAF){
		if(max - *pos < 1)
			return false;
		dst[(*pos)++] = NODE_LEAF;
		return AccountData::Serialize(dst,pos,max);
	}else{
		if(max - *pos < 22)
			return false;
		dst[(*pos)++] = NODE_BRANCH;
		dst[(*pos)++] = m_key_bits;
		SerializeHash(dst,pos,m_key);
	}
	return true;
}

uint32_t TrieNode::DeserializeI(uint8_t *src, uint32_t sz){
	if(m_type==NODE_HASH){
		m_modified=false;
		if(sz<32){
			printf("Fail Hash: %d\n", sz);
			return 0;
		}
		DeserializeHash(&m_hash,src);
		return 32;
	}

	if(m_type==NODE_BRANCH){
		//printf("Branch %d\n", sz);
		if(sz<23){
			printf("Fail branch 1: %d\n", sz);
			return 0;
		}
		m_key_bits=*src++; sz--;
		DeserializeHash(&m_key,src);
		src+=20;
		sz-=20;

		//cout << m_key.GetHex() << endl;
	
		//Load left
		if(sz<21){
			printf("Fail branch 2: %d\n", sz);
			return 0;
		}
		if(*src < NODE_LEAF || *src > NODE_HASH){
			printf("Fail branch 3: %d\n", sz);
			return 0;
		}
		//printf("tick\n");
		m_left = new TrieNode(*src++); sz--;
		uint32_t nsz = m_left->DeserializeI(src,sz);
		if(nsz==0){
			printf("Fail branch 4: %d\n", sz);
			delete m_left; m_left=0; return 0;
		}
		sz-=nsz;
		src+=nsz;

		//m_left->Print();

		//printf("tock %d\n", *src);

		//Load right
		if(sz<21){
			printf("Fail branch 5: %d\n", sz);
			return 0;
		}
		if(*src < NODE_LEAF || *src > NODE_HASH){
			return 0;
		}
		m_right = new TrieNode(*src++); sz--;
		uint32_t nsz2 = m_right->DeserializeI(src,sz);
		if(nsz2==0){
			delete m_right; m_right=0; return 0;
		}
		sz-=nsz2;
		src+=nsz2;

		return 23 + nsz+nsz2; //Have to include the 2 header bytes
	}

	if(m_type==NODE_LEAF){
		//printf("Leaf\n");
		return AccountData::DeserializeI(src,sz);
	}

	printf("Unknown type!!! %d\n", sz);
	return 0;
}

TrieNode* TrieNode::Deserialize(uint8_t *src, uint32_t sz){
	if(sz<33)
		return 0;
	if(*src < NODE_LEAF || *src > NODE_HASH)
		return 0;
	TrieNode* ret = new TrieNode(*src++); sz--;
	//0 means trie did not deserialize
	if(!ret->DeserializeI(src,sz)){
		printf("Fail\n");
		delete ret; return 0;
	}
	//trie needs a little cleanup before return. parenting and child counts
	TrieEngine::RebuildStructure(ret);
	return ret;
}

//Fast source of entropy
unsigned long long rdtsc(){
    unsigned int lo,hi;
    __asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
    return ((unsigned long long)hi << 32) | lo;
}

void TrieNode::Parentify(TrieNode *parent){
	if(parent){
		m_parent = parent;
	}

	if(m_left)
		m_left->Parentify(this);
	if(m_right)
		m_right->Parentify(this);	
}

uint64_t TrieNode::FindChildren(){
	if(m_type == NODE_BRANCH){
		m_children = m_left->FindChildren() + m_right->FindChildren();
		return m_children+1;
	}else{
		return 1;
	}
}

void TrieNode::FindAll(uint32_t type, list<TrieNode*> *ret){
	if(m_type==type)
		ret->push_back(this);
	if(m_left)
		m_left->FindAll(type,ret);
	if(m_right)
		m_right->FindAll(type,ret);
}

uint160_t TrieNode::GetTotalKey(TrieNode* child, uint160_t key){
	uint160_t bit=child==m_right?1:0;
	key = m_key | key | (bit << (160-GetTotalBits()));
	if(m_parent)
		return m_parent->GetTotalKey(this,key);
	return key;
}


#define N_HASHES 10000
#define N_REMOVE 9990

#ifdef DEBUG_TRIE
void lurp(){
	uint32_t i;
	//Create some nodes for testing
	unsigned seed = rdtsc();
	printf("Seed: %u\n", seed);
	srand ( seed );

	vector<TrieNode*> nodes, removes;
	for(i=0; i < N_HASHES; i++){
		TrieNode* node = new TrieNode(NODE_LEAF);
		node->SetKey(GetRandHash()>>0);
		nodes.push_back(node);
		//cout << "Hash: " << nodes[i]->Key().GetHex() << "\n";
	}
	cout << "Hash: " << nodes[0]->Hash().GetHex() << "\n";

	random_shuffle(nodes.begin(),nodes.end());

	TrieNode *root = 0;
	for(i=0; i < nodes.size(); i++){
		TrieEngine::Insert(&root,nodes[i]);
//		root->Print();
	}

//	root->Print();

	printf("Count: %ld\n", TrieEngine::Size(root));


	cout << "Hash: " << root->Hash().GetHex() << "\n";

	//Serialize a subtree
	uint8_t *buf = new uint8_t[1024*1024];
	uint32_t sz=0;
	uint160_t left,right;

	if(root){
		//root->Print();
		left= ((uint160_t)1) << 159; //nodes[rand()%N_HASHES]->Key()+10000;
		right = left + 10000;
		TrieEngine::SubTrie(root,left,right,buf,&sz,1024*1024);
		printf("Serialized %d bytes %s %s\n", sz, left.GetHex().c_str(), right.GetHex().c_str());
#if 0
		for(i=0; i < sz; i++){
			printf("%2.2X ", buf[i]);
		}
		printf("\n");
#endif
	}

	if(root)
		delete root;

	root = TrieNode::Deserialize(buf,sz);
	if(root){
		cout << "Hash: " << root->Hash().GetHex() << "\n";
		root->Print();
		cout << root->Children() << endl;
		bool valid = TrieEngine::Prove(root,left,right);
		printf("Trie was valid? %d\n", valid);
		assert(valid);
		delete root;
	}

	delete[] buf;

	nodes.clear();
	removes.clear();
}

int main(){
#if 0
	random_shuffle(nodes.begin(),nodes.end());
	for(i=0; i < N_REMOVE && i < nodes.size(); i++){
		removes.push_back(nodes[i]);
	}

	srand ( rdtsc() );
	random_shuffle(removes.begin(),removes.end());
	for(i=0; i < removes.size(); i++){
		TrieEngine::Remove(&root,removes[i]);
	}

	printf("Count: %ld\n", TrieEngine::Size(root));

	cout << "Hash: " << root->Hash().GetHex() << "\n";
#endif
	while(1)
		lurp();

	return 0;
}	
#endif

