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
#include <list>

#include "uint256.h"
#include "hash.h"
#include "trie.h"

using namespace std;

static uint160_t sub_key(uint160_t key, uint32_t left, uint32_t size){
	return ((key << left) >> (160 - size)) << (160 - size - left);
}

static uint32_t high_bit(uint160_t key, uint32_t shift){
	key = key >> (160 - shift - 1);
	return *key.begin() & 1;
}

//Function to insert into trie
void TrieEngine::Insert(TrieNode **root, TrieNode *node, uint32_t bits){
	if(*root==0){
		*root = node;
		node->SetParent(0);
		return;
	}

	if((*root)->Type() == NODE_BRANCH){
		//First check if we need to split the branch
		uint32_t new_bits = (*root)->Bits();
		uint160_t subkey=sub_key(node->Key(), bits, new_bits);//(key>>(256-(new_bits-1)))<<(256-(new_bits-1));
		//cout << "Subkey: " << subkey.GetBin() << "\n";
		if(subkey == (*root)->Key()){
			//printf("Got match\n");
			//Can move down tree
			uint32_t bit=high_bit(node->Key(), bits + new_bits);//Find bottom bit of subkey
			if(bit & 1){ //Right side
				Insert(&(*root)->m_right,node,bits+new_bits+1);
			}else{
				Insert(&(*root)->m_left,node,bits+new_bits+1);
			}
			return;
		}
		//return;
		//If we get here, then the branch at root needs to be split and another branch inserted
		
	}

	if(1){ //(*root)->Type() == NODE_LEAF
		TrieNode *parent = (*root)->Parent();

		//Uh ohs!!!!!
		TrieNode *node2 = *root;
		//Add the nodes with lower node on left.
		uint160_t k1 = node->Key() << bits;
		uint160_t k2 = node2->Key() << bits; 

		assert(k1!=k2); //Duplicate insert attempt;

		if(parent){
			//we must deparent the leaf first to get counts under control
			parent->Subtract((*root)->Children());
			//assert(0);
		}

		//Create a new node to hold the branch
		*root = new TrieNode(NODE_BRANCH);
		(*root)->SetParent(parent);
		
		if(k1 < k2){
			(*root)->Add(node);
			(*root)->Add(node2);	
		}else{
			(*root)->Add(node2);
			(*root)->Add(node);
		}

		//cout << "k1: " << k1.GetBin() << "\n";
		//cout << "k2: " << k2.GetBin() << "\n";

		//Determine how many bits are common
		uint8_t c1,c2;
		uint32_t new_bits=0;
		do{
			c1 = *(k1.end()-1);
			c2 = *(k2.end()-1);

			//printf("%X %X %X %X\n", c1, c2, c1 ^ c2, (c1 ^ c2) & 0x80);

			k1 = k1 << 1;
			k2 = k2 << 1;
			new_bits++;
		}while(((c1 ^ c2) & 0x80) == 0);
		new_bits--;
		(*root)->SetBits(new_bits);

		//printf("new bits %d\n", new_bits);

		//Common is  new_bits  
		(*root)->SetKey(sub_key(node->Key(), bits, new_bits));

		//Should be good to go

		//If we just broke a branch, we need to update the childs hash crap
#if 1
		if(node->Type() == NODE_BRANCH || node2->Type() == NODE_BRANCH){
			//printf("Foo1111\n");
			TrieNode *branch = node;
			if(node2->Type() == NODE_BRANCH)
				branch = node2;

			branch->SetBits(branch->Bits()-new_bits-1);
			branch->SetKey(sub_key(branch->Key(), bits + new_bits+1, branch->Bits()));
		}
#endif
	}
}

void TrieEngine::Remove(TrieNode **root, TrieNode *node){
	TrieNode *parent = node->Parent();
	if(!parent){
		*root = 0;
		delete node;
		return;
	}

	//Remove node from parent. If other child of parent is leaf, then reparent leaf to parents parent
	//If other child is branch, then combine the branched and reparent to parents parent
	TrieNode *peer = parent->Remove(node);
	delete node;

	if(!parent->Parent()){
		*root = peer;
		peer->SetParent(0);
	}else{
		parent->Parent()->Replace(parent,peer);
	}

	{
		if(peer->Type() == NODE_BRANCH){
			peer->SetBits(peer->Bits() + parent->Bits() + 1);
			uint32_t total = parent->GetTotalBits();
			peer->SetKey(peer->Key() | parent->Key()); 
			if(parent->m_right==peer){
				uint160_t foo = 1;
				foo = foo << (160 - total);
				peer->SetKey(peer->Key() | foo);
			}
		}
		//Must set parent to null because this node is orphaned and we don't want it propagating count updates
		parent->SetParent(0);
		//Must remove the peer from parent before delete or it will try to delete good nodes
		parent->Remove(peer);
		delete parent;
	}
}

uint64_t TrieEngine::Size(TrieNode* root){
	if(!root)
		return 0;
	return root->Children();
}

void SerializeHash(uint8_t *dst, uint32_t *pos, uint256_t hash){
	memcpy(dst+*pos,&hash,32);
	*pos+=32;
}

void DeserializeHash(uint256_t *hash,uint8_t *src){
	memcpy(hash,src,32);
}

void SerializeHash(uint8_t *dst, uint32_t *pos, uint160_t hash){
	memcpy(dst+*pos,&hash,20);
	*pos+=20;
}

void DeserializeHash(uint160_t *hash,uint8_t *src){
	memcpy(hash,src,20);
}

bool hashNode(TrieNode* root,uint8_t *dst, uint32_t *pos, uint32_t max){
	if(max - *pos < 33)
		return false;
	dst[(*pos)++] = NODE_HASH;
	uint256_t hash = root->Hash();
	SerializeHash(dst,pos,hash);
	return true;
}

bool TrieEngine::SubTrie(TrieNode* root, uint160_t left, uint160_t right, uint8_t *dst, uint32_t *pos, uint32_t max, uint32_t *nodes, uint160_t ckey, uint32_t bits, bool hashOnly){
	uint160_t ones;
	memset(&ones,0xFF,20);

	if(hashOnly)
		return hashNode(root,dst,pos,max);
	if(root->Type() == NODE_LEAF){
		(*nodes)++;
		return root->Serialize(dst,pos,max);
	}else{
		bits+=root->Bits();
		ckey |= root->Key();
		uint160_t maxkey = ckey | (((uint160_t)1) << (160-bits-1));
		uint160_t mask = ~(ones >> (bits+1));

//		cout << maxkey.GetHex() << ", " << ckey.GetHex() << ", " << left.GetHex() << ", " << mask.GetHex().c_str() << endl;
		bool hashLeft=false;
		bool hashRight=false;

		if(ckey < (left & mask))
		    hashLeft = true;

		if(maxkey < (left & mask))
		    hashRight = true;

		if(maxkey > right){
//			hashLeft=true;
			hashRight=true;
		}


		if(!root->Serialize(dst,pos,max))
			return false;

		if(!SubTrie(root->m_left,left,right,dst,pos,max,nodes,ckey,bits+1,hashLeft))
			return false;
		if(!SubTrie(root->m_right,left,right,dst,pos,max,nodes,maxkey,bits+1,hashRight))
			return false;
	}
	return true;
}

void TrieEngine::RebuildStructure(TrieNode *root){
	root->Parentify(0);
	root->FindChildren();
}

void TrieEngine::TraverseLeft(TrieNode *leftnode, uint160_t left, uint160_t right, list<TrieNode*> *lefts, int bits) {
	uint160_t ones;
	memset(&ones,0xFF,20);
	if(leftnode){
		if(leftnode->Type()==NODE_BRANCH){
			bits+=leftnode->Bits();
			uint160 tkey = leftnode->GetTotalKey(leftnode->m_left,0);
			uint160_t mask = ~(ones >> (bits+1));
			uint160 rtkey = leftnode->GetTotalKey(leftnode->m_right,0);

			if(tkey < (left&mask)){
				leftnode->FindAll(NODE_HASH,lefts);
				return;
			}else{
				TraverseLeft(leftnode->m_left, left, right, lefts, bits);
			}
			if(rtkey < (left&mask)){
				leftnode->m_right->FindAll(NODE_HASH,lefts);
				return;
			}else{
				TraverseLeft(leftnode->m_right, left, right, lefts, bits);
			}
		}
	}
}

void TrieEngine::TraverseRight(TrieNode *rightnode, uint160_t left, uint160_t right, list<TrieNode*> *rights, int bits) {
	uint160_t ones;
	memset(&ones,0xFF,20);
	if(rightnode){
		if(rightnode->Type()==NODE_BRANCH){
			bits+=rightnode->Bits();
			uint160 rtkey = rightnode->GetTotalKey(rightnode->m_right,0);

			if(rtkey > right){
				rightnode->FindAll(NODE_HASH,rights);
				return;
			}else{
				TraverseRight(rightnode->m_right, left, right, rights, bits);
			}
			if(rtkey > left){
				rightnode->m_left->FindAll(NODE_HASH,rights);
				return;
			}else{
				TraverseRight(rightnode->m_left, left, right, rights, bits);
			}
		}
	}
}

bool TrieEngine::Prove(TrieNode *root, uint160_t left, uint160_t right){
	uint160_t ones;
	memset(&ones,0xFF,20);

	//Principle here is that we will traverse the trie. locating all hash only nodes to the left of the left bound
	//and to the right of the right bound. If the union of these sets contains all hash nodes in the subtrie, then
	//the subtrie *must* contain all real nodes between left and right. 

	//Locate all hash nodes to the left of left
	list<TrieNode*> lefts;
	TraverseLeft(root, left, right, &lefts, 0);

	//Do right traversal
	list<TrieNode*> rights;
	TraverseRight(root, left, right, &rights, 0);

	//For sanity check we must find all hash nodes
	list<TrieNode*> hashnodes;
	root->FindAll(NODE_HASH,&hashnodes);

	//lefts+rights can be larger than hashnodes in degenerate cases, so we ignore failure to remove
	//as it is impossible that union of lefts+rights contains elements not in hashnodes
	list<TrieNode*>::iterator it;
	for(it = lefts.begin(); it!= lefts.end(); it++){
		hashnodes.remove(*it);
	}
	for(it = rights.begin(); it != rights.end(); it++){
		hashnodes.remove(*it);
	}

	if(!hashnodes.empty()){
		//Bastard tried to sneak a fast one on us
		printf("Bad trie!\n");
		return false;
	}
#if 0
	//Very last elements in list are the bounding elements of the recieved data
	//Warning, lists may be empty if trie is unbounded on either side!
	TrieNode* leftBound = lefts.empty()?0:lefts.back();
	TrieNode* rightBound = rights.empty()?0:rights.back();

	printf("%p %p %ld %ld\n", leftBound, rightBound, lefts.size(), rights.size());

	//////////////////////At this point we know the trie is well formed. Just a matter of locating the bounds
	uint160_t leftcalc,rightcalc;
	if(leftBound){
		uint32_t bits = leftBound->Parent()->GetTotalBits();
		uint160_t key = ones >> bits;
		uint160_t key2 = leftBound->Parent()->GetTotalKey(leftBound,0);
		leftcalc = key|key2;
	}else{
		leftcalc = 0;
	}

	//TODO: Pretty sure right bound is wrong
	if(rightBound){
		//uint32_t bits = rightBound->Parent()->GetTotalBits();
		uint160_t key = 0;//ones >> bits;
		uint160_t key2 = rightBound->Parent()->GetTotalKey(rightBound,0);
		rightcalc=key|key2;
	}else{
		//If there are no empty nodes on right then the bound is maximal
		rightcalc=ones;
	}

	//Really weird degenerate cases
	if(leftcalc != 0 && rightcalc < leftcalc)
		rightcalc = ones;

	if(rightcalc != ones && rightcalc < leftcalc)
		leftcalc = 0;
	cout << left.GetHex() << endl;
	cout << leftcalc.GetHex() << endl;
	cout << right.GetHex() << endl;
	cout << rightcalc.GetHex() << endl;

	return leftcalc <= left && rightcalc >= right;
#else
	return true;
#endif
}

TrieNode* TrieEngine::Find(uint160_t key, TrieNode *root, uint32_t keybits){
	if(!root)
		return 0;
	if(root->Type() == NODE_LEAF){
		//printf("Key: %s %s\n", key.GetHex().c_str(), root->Key().GetHex().c_str());
		if(root->Key() == key)
			return root;
		else
			return 0;
	}
	if(root->Type() != NODE_BRANCH)
		return 0;

	if(root->Type() == NODE_BRANCH){
		uint160_t skey = sub_key(key,keybits,root->Bits());
		uint160_t key2 = sub_key(root->Key(),keybits,root->Bits());
		//printf("Keys: %s, %s\n", skey.GetHex().c_str(), key2.GetHex().c_str());
		if(skey!=key2)
			return 0;

		if(((key >> (159 - (keybits + root->Bits()))) & 1) != 0){
			//printf("Right\n");
			return Find(key,root->m_right,keybits + root->Bits() + 1);
		} 
		//printf("Left\n");
		return Find(key,root->m_left,keybits + root->Bits() + 1); 
	}
	return 0;
}
