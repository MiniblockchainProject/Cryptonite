// Copyright (c) 2012-2013 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcserver.h"
#include "rpcclient.h"

#include "base58.h"

#include <boost/algorithm/string.hpp>
#include <boost/test/unit_test.hpp>

using namespace std;
using namespace json_spirit;

Array
createArgs(int nRequired, const char* address1=NULL, const char* address2=NULL)
{
    Array result;
    result.push_back(nRequired);
    Array addresses;
    if (address1) addresses.push_back(address1);
    if (address2) addresses.push_back(address2);
    result.push_back(addresses);
    return result;
}

Value CallRPC(string args)
{
    vector<string> vArgs;
    boost::split(vArgs, args, boost::is_any_of(" \t"));
    string strMethod = vArgs[0];
    vArgs.erase(vArgs.begin());
    Array params = RPCConvertValues(strMethod, vArgs);

    rpcfn_type method = tableRPC[strMethod]->actor;
    try {
        Value result = (*method)(params, false);
        return result;
    }
    catch (Object& objError)
    {
        throw runtime_error(find_value(objError, "message").get_str());
    }
}


BOOST_AUTO_TEST_SUITE(rpc_tests)

BOOST_AUTO_TEST_CASE(rpc_rawparams)
{
    // Test raw transaction API argument handling
    Value r;

    BOOST_CHECK_THROW(CallRPC("getrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction not_hex"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("getrawtransaction a3b807410df0b60fcb9736768df5823938b2f838694939ba45f3c0a1bff150ed not_int"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("createrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction null null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction not_array"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] []"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("createrawtransaction [] {}"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC("createrawtransaction {} {}"));
    BOOST_CHECK_THROW(CallRPC("createrawtransaction {} {} extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("decoderawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("decoderawtransaction DEADBEEF"), runtime_error);
    string rawtx = "01000000017f3751cc56298d6f41030571ac6e98ff0dc6487e00f2052a01000000420105a1a5746897f752952f865ef7637791c92499c48c997c6407749ec2ba822f07e78718dcf90e2b9fe7194072a21d1eb622ca87ce55e82ba885743dad5c056356fd0100f2052a010000008e8916c13bb28898ea71b0a70fc930d6b05e99ff000000000000000000";
    BOOST_CHECK_NO_THROW(r = CallRPC(string("decoderawtransaction ")+rawtx));
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "version").get_int(), 1);
    BOOST_CHECK_EQUAL(find_value(r.get_obj(), "lockheight").get_int(), 0);
    BOOST_CHECK_THROW(r = CallRPC(string("decoderawtransaction ")+rawtx+" extra"), runtime_error);

    BOOST_CHECK_THROW(CallRPC("signrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("signrawtransaction ff00"), runtime_error);
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx+" null"));
    BOOST_CHECK_NO_THROW(CallRPC(string("signrawtransaction ")+rawtx+" []"));

    // Only check failure cases for sendrawtransaction, there's no network to send to...
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction null"), runtime_error);
    BOOST_CHECK_THROW(CallRPC("sendrawtransaction DEADBEEF"), runtime_error);
    BOOST_CHECK_THROW(CallRPC(string("sendrawtransaction ")+rawtx+" extra"), runtime_error);
}

#if 0
BOOST_AUTO_TEST_CASE(rpc_rawsign)
{

    Value r;
    // input is a 1-of-2 multisig (so is output):
    string prevout =
      "[{\"txid\":\"b4cc287e58f87cdae59417329f710f3ecd75a4ee1d2872b7248f50977c8493f3\","
      "\"vout\":1,\"scriptPubKey\":\"a914b10c9df5f7edf436c697f02f1efdba4cf399615187\","
      "\"redeemScript\":\"512103debedc17b3df2badbcdd86d5feb4562b86fe182e5998abd8bcd4f122c6155b1b21027e940bb73ab8732bfdf7f9216ecefca5b94d6df834e77e108f68e66f126044c052ae\"}]";
    r = CallRPC(string("createrawtransaction ")+prevout+" "+
      "{\"3HqAe9LtNBjnsfM4CyYaWTnvCaUYT7v4oZ\":11}");
    string notsigned = r.get_str();
    string privkey1 = "\"KzsXybp9jX64P5ekX1KUxRQ79Jht9uzW7LorgwE65i5rWACL6LQe\"";
    string privkey2 = "\"Kyhdf5LuKTRx4ge69ybABsiUAWjVRK4XGxAKk2FQLp2HjGMy87Z4\"";
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"[]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == false);
    r = CallRPC(string("signrawtransaction ")+notsigned+" "+prevout+" "+"["+privkey1+","+privkey2+"]");
    BOOST_CHECK(find_value(r.get_obj(), "complete").get_bool() == true);
}
#endif


BOOST_AUTO_TEST_CASE(rpc_format_monetary_values)
{
    BOOST_CHECK(ValueFromAmount(0LL).get_str() == "0.00000000ep");
    BOOST_CHECK(ValueFromAmount(1LL).get_str() == "0.00000001ep");
    BOOST_CHECK(ValueFromAmount(17622195LL).get_str() == "0.17622195ep");
    BOOST_CHECK(ValueFromAmount(50000000LL).get_str() == "0.50000000ep");
    BOOST_CHECK(ValueFromAmount(89898989LL).get_str() == "0.89898989ep");
    BOOST_CHECK(ValueFromAmount(100000000LL).get_str() == "1.00000000ep");
    BOOST_CHECK(ValueFromAmount(2099999999999990LL).get_str() == "20999999.99999990ep");
    BOOST_CHECK(ValueFromAmount(2099999999999999LL).get_str() == "20999999.99999999ep");
}

static Value ValueFromString(const std::string &str)
{
    Value value;
    BOOST_CHECK(read_string(str, value));
    return value;
}

BOOST_AUTO_TEST_CASE(rpc_parse_monetary_values)
{
    BOOST_CHECK(AmountFromValue(ValueFromString("\"0.00000001ep\"")) == 1LL);
    BOOST_CHECK(AmountFromValue(ValueFromString("\"0.17622195ep\"")) == 17622195LL);
    BOOST_CHECK(AmountFromValue(ValueFromString("\"0.50000000ep\"")) == 50000000LL);
    BOOST_CHECK(AmountFromValue(ValueFromString("\"0.89898989ep\"")) == 89898989LL);
    BOOST_CHECK(AmountFromValue(ValueFromString("\"1.00000000ep\"")) == 100000000LL);
    BOOST_CHECK(AmountFromValue(ValueFromString("\"20999999.99999999ep\"")) == 2099999999999999LL);
}

BOOST_AUTO_TEST_SUITE_END()
