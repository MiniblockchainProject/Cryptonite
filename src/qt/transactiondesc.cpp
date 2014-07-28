// Copyright (c) 2011-2014 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactiondesc.h"

#include "bitcoinunits.h"
#include "guiutil.h"

#include "base58.h"
#include "db.h"
#include "main.h"
#include "paymentserver.h"
#include "transactionrecord.h"
#include "ui_interface.h"
#include "wallet.h"

#include <stdint.h>
#include <string>

QString TransactionDesc::FormatTxStatus(const CWalletTx& wtx)
{
    int nDepth = GetDepthInMainChain(wtx.GetTxID());
    if ( (int64_t)wtx.nLockHeight > chainActive.Height() + 1)
    {
       return tr("Open for %n more block(s)", "", wtx.nLockHeight - chainActive.Height());
    }
    else if( (int64_t)(wtx.nLockHeight + MIN_HISTORY) < chainActive.Height() && nDepth == -1){
       return tr("Unknown");
    }
    else
    {
        if (nDepth < 0)
            return tr("conflicted");
	else if (nDepth == 0)
            return tr("unconfirmed");
        else if (nDepth < 6)
            return tr("%1/confirming").arg(nDepth);
        else
            return tr("%1 confirmations").arg(nDepth);
    }
}

QString TransactionDesc::toHTML(CWallet *wallet, CWalletTx &wtx, int vout, int unit)
{
    QString strHTML;

    {
        LOCK(wallet->cs_wallet);
        strHTML.reserve(4000);
        strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

        int64_t nTime = wtx.GetTxTime();
        int64_t nCredit = wtx.GetCredit();
        int64_t nDebit = wtx.GetDebit();
        int64_t nNet = nCredit - nDebit;

        strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(wtx) + "<br>";

        strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";
        //
        // From
        //
        if (wtx.IsCoinBase())
        {
            strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
        }
        else if (wtx.mapValue.count("from") && !wtx.mapValue["from"].empty())
        {
            // Online transaction
            strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.mapValue["from"]) + "<br>";
        }
        else
        {
            // Offline transaction
            if (nNet > 0)
            {
                // Credit
                BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                {
                    if (wallet->IsMine(txout))
                    {
                        CTxDestination address = CKeyID(txout.pubKey);
                        if (wallet->IsMine(txout.pubKey))
                        {
                            if (wallet->mapAddressBook.count(address))
                            {
                                strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                                strHTML += "<b>" + tr("To") + ":</b> ";
                                strHTML += GUIUtil::HtmlEscape(CBitcoinAddress(address).ToString());
                                if (!wallet->mapAddressBook[address].name.empty())
                                    strHTML += " (" + tr("own address") + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                                else
                                    strHTML += " (" + tr("own address") + ")";
                                strHTML += "<br>";
                            }
                        }
                        break;
                    }
                }
            }
        }

        //
        // To
        //
        if (wtx.mapValue.count("to") && !wtx.mapValue["to"].empty())
        {
            // Online transaction
            std::string strAddress = wtx.mapValue["to"];
            strHTML += "<b>" + tr("To") + ":</b> ";
            CTxDestination dest = CBitcoinAddress(strAddress).Get();
            if (wallet->mapAddressBook.count(dest) && !wallet->mapAddressBook[dest].name.empty())
                strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[dest].name) + " ";
            strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
        }

        //
        // Amount
        //
        if (nNet > 0)
        {
            //
            // Credit
            //
            strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, nNet) + "<br>";
        }
        else
        {
            bool fAllFromMe = true;
            BOOST_FOREACH(const CTxIn& txin, wtx.vin)
                fAllFromMe = fAllFromMe && wallet->IsMine(txin);

            bool fAllToMe = true;
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                fAllToMe = fAllToMe && wallet->IsMine(txout);

            if (fAllFromMe)
            {
                //
                // Debit
                //
                BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                {
                    if (wallet->IsMine(txout))
                        continue;

                    if (!wtx.mapValue.count("to") || wtx.mapValue["to"].empty())
                    {
                        // Offline transaction
                        CTxDestination address = CKeyID(txout.pubKey);
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += GUIUtil::HtmlEscape(CBitcoinAddress(address).ToString());
                        strHTML += "<br>";
                    }

                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, -txout.nValue) + "<br>";
                }

                if (fAllToMe)
                {
                    // Payment to self
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, nDebit) + "<br>";
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, nCredit) + "<br>";
                }

                uint64_t nTxFee = nDebit - wtx.GetValueOut();
                if (nTxFee > 0)
                    strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatWithUnit(unit, nTxFee) + "<br>";
            }
            else
            {
                //
                // Mixed debit transaction
                //
                BOOST_FOREACH(const CTxIn& txin, wtx.vin)
                    if (wallet->IsMine(txin))
                        strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, wallet->GetDebit(txin)) + "<br>";
                BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                    if (wallet->IsMine(txout))
                        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, wallet->GetCredit(txout)) + "<br>";
            }
        }

        strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatWithUnit(unit, nNet, true) + "<br>";


        //
        // Message
        //
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(string(wtx.msg.begin(),wtx.msg.end()), true) + "<br>";

        strHTML += "<b>" + tr("Transaction ID") + ":</b> " + QString::fromStdString(wtx.GetTxID().ToString()) + "<br>";
#if 0 //TODO: wtf is this stuff?
        // Message from normal bitcoin:URI (bitcoin:123...?message=example)
        foreach (const PAIRTYPE(string, string)& r, wtx.vOrderForm)
            if (r.first == "Message")
                strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

        //
        // PaymentRequest info:
        //
        foreach (const PAIRTYPE(string, string)& r, wtx.vOrderForm)
        {
            if (r.first == "PaymentRequest")
            {
                PaymentRequestPlus req;
                req.parse(QByteArray::fromRawData(r.second.data(), r.second.size()));
                QString merchant;
                if (req.getMerchant(PaymentServer::getCertStore(), merchant))
                    strHTML += "<b>" + tr("Merchant") + ":</b> " + GUIUtil::HtmlEscape(merchant) + "<br>";
            }
        }
#endif
        //
        // Debug view
        //
        if (fDebug)
        {
            strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
            BOOST_FOREACH(const CTxIn& txin, wtx.vin)
                if(wallet->IsMine(txin))
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, wallet->GetDebit(txin)) + "<br>";
            BOOST_FOREACH(const CTxOut& txout, wtx.vout)
                if(wallet->IsMine(txout))
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatWithUnit(unit, wallet->GetCredit(txout)) + "<br>";

            strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
            strHTML += GUIUtil::HtmlEscape(wtx.ToString(), true);

            strHTML += "<br><b>" + tr("Inputs") + ":</b>";
            strHTML += "<ul>";

            {
                LOCK(wallet->cs_wallet);
                BOOST_FOREACH(const CTxIn& txin, wtx.vin)
                {
                    strHTML += "<li>";
                    CTxDestination address = CKeyID(txin.pubKey);
                    if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                        strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                    strHTML += QString::fromStdString(CBitcoinAddress(address).ToString());

                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatWithUnit(unit, txin.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet->IsMine(txin.pubKey) ? tr("true") : tr("false")) + "</li>";
                }
            }

            strHTML += "</ul>";
        }

        strHTML += "</font></html>";
    }
    return strHTML;
}
