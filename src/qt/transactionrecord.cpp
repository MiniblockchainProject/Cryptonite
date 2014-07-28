// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionrecord.h"

#include "base58.h"
#include "wallet.h"

#include <stdint.h>

/* Return positive answer if transaction should be shown in list.
 */
bool TransactionRecord::showTransaction(const CWalletTx &wtx)
{
    if (wtx.IsCoinBase())
    {
        // Ensures we show generated coins / mined transactions at depth 1
//TODO:
//        if (!wtx.IsInMainChain())
//        {
//            return false;
//        }
    }
    return true;
}

/*
 * Decompose CWallet transaction to model transaction records.
 */
QList<TransactionRecord> TransactionRecord::decomposeTransaction(const CWallet *wallet, const CWalletTx &wtx)
{
    QList<TransactionRecord> parts;
    int64_t nTime = wtx.GetTxTime();
    int64_t nCredit = wtx.GetCredit(true);
    int64_t nDebit = wtx.GetDebit();
    int64_t nNet = nCredit - nDebit;
    uint256 hash = wtx.GetTxID();
    std::map<std::string, std::string> mapValue = wtx.mapValue;

    if (nNet > 0 || wtx.IsCoinBase())
    {
        //
        // Credit
        //
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
        {
            if(wallet->IsMine(txout))
            {
                TransactionRecord sub(hash, nTime);
                CTxDestination address = CKeyID(txout.pubKey);
                sub.idx = parts.size(); // sequence number
                sub.credit = txout.nValue;
                if (wallet->IsMine(txout.pubKey))
                {
                    // Received by Bitcoin Address
                    sub.type = TransactionRecord::RecvWithAddress;
                    sub.address = CBitcoinAddress(address).ToString();
                }
                else
                {
                    // Received by IP connection (deprecated features), or a multisignature or other non-simple transaction
                    sub.type = TransactionRecord::RecvFromOther;
                    sub.address = mapValue["from"];
                }
                if (wtx.IsCoinBase())
                {
                    // Generated
                    sub.type = TransactionRecord::Generated;
                }

                parts.append(sub);
            }
        }
    }
    else
    {
        bool fAllFromMe = true;
        BOOST_FOREACH(const CTxIn& txin, wtx.vin)
            fAllFromMe = fAllFromMe && wallet->IsMine(txin);

        bool fAllToMe = true;
        BOOST_FOREACH(const CTxOut& txout, wtx.vout)
            fAllToMe = fAllToMe && wallet->IsMine(txout);

	if(wtx.fSetLimit){
            // Payment to self
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::SetLimit, "",
                            wtx.nLimitValue, 0));
	}
        else if (fAllFromMe && fAllToMe)
        {
            // Payment to self
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::SendToSelf, "",
                            -(nDebit), nCredit));
        }
        else if (fAllFromMe)
        {
            //
            // Debit
            //
            int64_t nTxFee = nDebit - wtx.GetValueOut();

            for (unsigned int nOut = 0; nOut < wtx.vout.size(); nOut++)
            {
                const CTxOut& txout = wtx.vout[nOut];
                TransactionRecord sub(hash, nTime);
                sub.idx = parts.size();

                if(wallet->IsMine(txout))
                {
                    // Ignore parts sent to self, as this is usually the change
                    // from a transaction sent back to our own address.
                    continue;
                }

                CTxDestination address = CKeyID(txout.pubKey);
                // Sent to Bitcoin Address
                sub.type = TransactionRecord::SendToAddress;
                sub.address = CBitcoinAddress(address).ToString();

                int64_t nValue = txout.nValue;
                /* Add fee to first output */
                if (nTxFee > 0)
                {
                    nValue += nTxFee;
                    nTxFee = 0;
                }
                sub.debit = -nValue;

                parts.append(sub);
            }
        }
        else
        {
            //
            // Mixed debit transaction, can't break down payees
            //
            parts.append(TransactionRecord(hash, nTime, TransactionRecord::Other, "", nNet, 0));
        }
    }

    return parts;
}

void TransactionRecord::updateStatus(const CWalletTx &wtx)
{
    // Determine transaction status

#if 0
    // Find the block the tx is in
    CBlockIndex* pindex = NULL;
    std::map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(wtx.hashBlock);
    if (mi != mapBlockIndex.end())
        pindex = (*mi).second;
#endif
    status.countsForBalance = true; //TODO: Wtf this do?
    status.depth = GetDepthInMainChain(wtx.GetTxID());
    status.cur_num_blocks = chainActive.Height();

    // Sort order, unrecorded transactions sort to the top
    status.sortKey = strprintf("%010d-%01d-%010u-%03d",
        (status.depth > 0 ? (chainActive.Height() - status.depth) : std::numeric_limits<int>::max()),
        (wtx.IsCoinBase() ? 1 : 0),
        wtx.nTimeReceived,
        idx);

    if ((int64_t)wtx.nLockHeight > chainActive.Height() + 1)
    {
        status.status = TransactionStatus::OpenUntilBlock;
        status.open_for = wtx.nLockHeight - chainActive.Height();
    }
    else if( (int64_t) (wtx.nLockHeight + MIN_HISTORY) < chainActive.Height() && status.depth == -1){
	status.status = TransactionStatus::Unknown;

        // Change sort key so these go to bottom
        status.sortKey = strprintf("%010d-%01d-%010u-%03d",
           0,
           (wtx.IsCoinBase() ? 1 : 0),
           wtx.nTimeReceived,
           idx);
    }
    // For generated transactions, determine maturity
    else if(type == TransactionRecord::Generated)
    {
        if (status.depth > 0)
        {
            status.status = TransactionStatus::Confirmed;
        }
        else
        {
            status.status = TransactionStatus::NotAccepted;
	    //Change sort order so these are ordered by block height
            status.sortKey = strprintf("%010d-%01d-%010u-%03d",
           	chainActive.Height() - wtx.nLockHeight,
           	1,
           	wtx.nTimeReceived,
           	idx);
        }
    }
    else
    {
        if (status.depth < 0)
        {
            status.status = TransactionStatus::Conflicted;
        }
#if 0 //TODO: not sure what this does
        else if (GetAdjustedTime() - wtx.nTimeReceived > 2 * 60 && wtx.GetRequestCount() == 0)
        {
            status.status = TransactionStatus::Offline;
        }
#endif
        else if (status.depth == 0)
        {
            status.status = TransactionStatus::Unconfirmed;
        }
        else if (status.depth < RecommendedNumConfirmations)
        {
            status.status = TransactionStatus::Confirming;
        }
        else
        {
            status.status = TransactionStatus::Confirmed;
        }
    }
}

bool TransactionRecord::statusUpdateNeeded()
{
    return status.cur_num_blocks != chainActive.Height();
}

QString TransactionRecord::getTxID() const
{
    return  QString::fromStdString(hash.ToString());
}

