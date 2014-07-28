include $(top_srcdir)/src/Makefile.include

AM_CPPFLAGS += -I$(top_srcdir)/src -std=c++11 -fpermissive -ffloat-store -D__STDC_LIMIT_MACROS

bin_PROGRAMS = test_bitcoin

TESTS = test_bitcoin

JSON_TEST_FILES = \
  data/script_valid.json \
  data/base58_keys_valid.json \
  data/sig_canonical.json \
  data/sig_noncanonical.json \
  data/base58_encode_decode.json \
  data/base58_keys_invalid.json \
  data/script_invalid.json \
  data/tx_invalid.json \
  data/tx_valid.json \
  data/sighash.json

JSON_H = \
  ../json/json_spirit.h \
  ../json/json_spirit_error_position.h \
  ../json/json_spirit_reader.h \
  ../json/json_spirit_reader_template.h \
  ../json/json_spirit_stream_reader.h \
  ../json/json_spirit_utils.h \
  ../json/json_spirit_value.h \
  ../json/json_spirit_writer.h \
  ../json/json_spirit_writer_template.h


RAW_TEST_FILES = data/alertTests.raw

BUILT_SOURCES = $(JSON_TEST_FILES:.json=.json.h) $(RAW_TEST_FILES:.raw=.raw.h)

# test_bitcoin binary #
test_bitcoin_CPPFLAGS = $(AM_CPPFLAGS) $(TESTDEFS)
test_bitcoin_LDADD = $(LIBBITCOIN_SERVER) $(LIBBITCOIN_CLI) $(LIBBITCOIN_COMMON) $(LIBLEVELDB) $(LIBMEMENV) \
  $(BOOST_LIBS) $(BOOST_UNIT_TEST_FRAMEWORK_LIB) 
if ENABLE_WALLET
test_bitcoin_LDADD += $(LIBBITCOIN_WALLET)
endif
test_bitcoin_LDADD += $(BDB_LIBS) -lgmp

test_bitcoin_SOURCES = \
  alert_tests.cpp \
  allocator_tests.cpp \
  base32_tests.cpp \
  base64_tests.cpp \
  bignum_tests.cpp \
  bloom_tests.cpp \
  checkblock_tests.cpp \
  Checkpoints_tests.cpp \
  compress_tests.cpp \
  getarg_tests.cpp \
  main_tests.cpp \
  mruset_tests.cpp \
  netbase_tests.cpp \
  rpc_tests.cpp \
  serialize_tests.cpp \
  uint256_tests.cpp \
  util_tests.cpp \
  test_bitcoin.cpp \
  $(JSON_H) \
  $(JSON_TEST_FILES) $(RAW_TEST_FILES)
#key_tests.cpp 
#base58_tests.cpp 
#DoS_tests.cpp 
#canonical_tests.cpp 
#miner_tests.cpp 
#multisig_tests.cpp 
#pmt_tests.cpp 
#script_P2SH_tests.cpp
#script_tests.cpp 
#sigopcount_tests.cpp 
#transaction_tests.cpp 
#sighash_tests.cpp

if ENABLE_WALLET
test_bitcoin_SOURCES += \
   rpc_wallet_tests.cpp
endif
#accounting_tests.cpp 
#wallet_tests.cpp 

nodist_test_bitcoin_SOURCES = $(BUILT_SOURCES)

CLEANFILES = *.gcda *.gcno $(BUILT_SOURCES)
