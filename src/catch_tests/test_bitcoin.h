// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_TEST_BITCOIN_H
#define BITCOIN_TEST_TEST_BITCOIN_H

#include <chainparamsbase.h>
#include <fs.h>
#include <key.h>
#include <pubkey.h>
#include <random.h>
#include <scheduler.h>
#include <txdb.h>
#include <txmempool.h>
#include <thread>

/**
 * Basic testing setup.
 * This just configures logging and chain parameters.
 */
struct BasicTestingSetup {
    ECCVerifyHandle globalVerifyHandle;

    explicit BasicTestingSetup(
        const std::string &chainName = CBaseChainParams::MAIN);
    ~BasicTestingSetup();
};

/** Testing setup that configures a complete environment.
 * Included are data directory, coins database, script check threads setup.
 */
class CConnman;
class CNode;
struct CConnmanTest {
    static void AddNode(CNode &node);
    static void ClearNodes();
};

class PeerLogicValidation;
struct TestingSetup : public BasicTestingSetup {
    fs::path pathTemp;
    std::vector<std::thread> threadGroup;
    CConnman *connman;
    CScheduler scheduler;

    explicit TestingSetup(
        const std::string &chainName = CBaseChainParams::MAIN);
    ~TestingSetup();
};

class CBlock;
class CMutableTransaction;
class CScript;

//
// Testing fixture that pre-creates a
// 100-block REGTEST-mode block chain
//
struct TestChain100Setup : public TestingSetup {
    TestChain100Setup();

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction> &txns,
                                 const CScript &scriptPubKey);

    ~TestChain100Setup();

    // For convenience, coinbase transactions.
    std::vector<CTransaction> coinbaseTxns;
    // private/public key needed to spend coinbase transactions.
    CKey coinbaseKey;
};

class CTxMemPoolEntry;
class CTxMemPool;

struct TestMemPoolEntryHelper {
    // Default values
    Amount nFee;
    int64_t nTime;
    unsigned int nHeight;
    bool spendsCoinbase;
    unsigned int sigOpCost;
    LockPoints lp;

    TestMemPoolEntryHelper()
        : nFee(), nTime(0), nHeight(1), spendsCoinbase(false), sigOpCost(4) {}

    CTxMemPoolEntry FromTx(const CMutableTransaction &tx);
    CTxMemPoolEntry FromTx(const CTransaction &tx);

    // Change the default value
    TestMemPoolEntryHelper &Fee(Amount _fee) {
        nFee = _fee;
        return *this;
    }
    TestMemPoolEntryHelper &Time(int64_t _time) {
        nTime = _time;
        return *this;
    }
    TestMemPoolEntryHelper &Height(unsigned int _height) {
        nHeight = _height;
        return *this;
    }
    TestMemPoolEntryHelper &SpendsCoinbase(bool _flag) {
        spendsCoinbase = _flag;
        return *this;
    }
    TestMemPoolEntryHelper &SigOpsCost(unsigned int _sigopsCost) {
        sigOpCost = _sigopsCost;
        return *this;
    }
};
#endif
