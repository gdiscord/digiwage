// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2019 The DIGIWAGE developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//#include "base58.h"
#include "key_io.h"
#include "checkpoints.h"
#include "clientversion.h"
#include "kernel.h"
#include "main.h"
#include "rpc/server.h"
#include "script/descriptor.h"
#include "sync.h"
#include "txdb.h"
#include "util.h"
#include "utilmoneystr.h"
#include "wallet/wallet.h"
#include "zpiv/zpivmodule.h"

#include <stdint.h>
#include <fstream>
#include <iostream>
#include <univalue.h>
#include <mutex>
#include <numeric>
#include <condition_variable>


struct CUpdatedBlock
{
    uint256 hash;
    int height;
};
static std::mutex cs_blockchange;
static std::condition_variable cond_blockchange;
static CUpdatedBlock latestblock;

extern void TxToJSON(const CTransaction& tx, const uint256 hashBlock, UniValue& entry);
void ScriptPubKeyToJSON(const CScript& scriptPubKey, UniValue& out, bool fIncludeHex);

double GetDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL) {
        if (chainActive.Tip() == NULL)
            return 1.0;
        else
            blockindex = chainActive.Tip();
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

UniValue blockheaderToJSON(const CBlockIndex* blockindex)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", blockindex->GetBlockHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", blockindex->nVersion));
    result.push_back(Pair("merkleroot", blockindex->hashMerkleRoot.GetHex()));
    result.push_back(Pair("time", (int64_t)blockindex->nTime));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)blockindex->nNonce));
    result.push_back(Pair("bits", strprintf("%08x", blockindex->nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));
    result.push_back(Pair("acc_checkpoint", blockindex->nAccumulatorCheckpoint.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex *pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));
    return result;
}

UniValue blockToJSON(const CBlock& block, const CBlockIndex* blockindex, bool txDetails = false)
{
    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hash", block.GetHash().GetHex()));
    int confirmations = -1;
    // Only report confirmations if the block is on the main chain
    if (chainActive.Contains(blockindex))
        confirmations = chainActive.Height() - blockindex->nHeight + 1;
    result.push_back(Pair("confirmations", confirmations));
    result.push_back(Pair("size", (int)::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION)));
    result.push_back(Pair("height", blockindex->nHeight));
    result.push_back(Pair("version", block.nVersion));
    result.push_back(Pair("merkleroot", block.hashMerkleRoot.GetHex()));
    result.push_back(Pair("acc_checkpoint", block.nAccumulatorCheckpoint.GetHex()));
    UniValue txs(UniValue::VARR);
    for (const CTransaction& tx : block.vtx) {
        if (txDetails) {
            UniValue objTx(UniValue::VOBJ);
            TxToJSON(tx, UINT256_ZERO, objTx);
            txs.push_back(objTx);
        } else
            txs.push_back(tx.GetHash().GetHex());
    }
    result.push_back(Pair("tx", txs));
    result.push_back(Pair("time", block.GetBlockTime()));
    result.push_back(Pair("mediantime", (int64_t)blockindex->GetMedianTimePast()));
    result.push_back(Pair("nonce", (uint64_t)block.nNonce));
    result.push_back(Pair("bits", strprintf("%08x", block.nBits)));
    result.push_back(Pair("difficulty", GetDifficulty(blockindex)));
    result.push_back(Pair("chainwork", blockindex->nChainWork.GetHex()));

    if (blockindex->pprev)
        result.push_back(Pair("previousblockhash", blockindex->pprev->GetBlockHash().GetHex()));
    CBlockIndex* pnext = chainActive.Next(blockindex);
    if (pnext)
        result.push_back(Pair("nextblockhash", pnext->GetBlockHash().GetHex()));

    result.push_back(Pair("moneysupply",ValueFromAmount(blockindex->nMoneySupply)));

    UniValue zwageObj(UniValue::VOBJ);
    for (auto denom : libzerocoin::zerocoinDenomList) {
        zwageObj.push_back(Pair(std::to_string(denom), ValueFromAmount(blockindex->mapZerocoinSupply.at(denom) * (denom*COIN))));
    }
    zwageObj.push_back(Pair("total", ValueFromAmount(blockindex->GetZerocoinSupply())));
    result.push_back(Pair("zerocoinsupply", zwageObj));

    //////////
    ////////// Coin stake data ////////////////
    /////////
    if (block.IsProofOfStake()) {
        uint256 hashProofOfStakeRet;
        if (!GetStakeKernelHash(hashProofOfStakeRet, block, blockindex->pprev))
            throw JSONRPCError(RPC_INTERNAL_ERROR, "Cannot get proof of stake hash");

        std::string stakeModifier = (Params().GetConsensus().IsStakeModifierV2(blockindex->nHeight) ?
                                     blockindex->GetStakeModifierV2().GetHex() :
                                     strprintf("%016x", blockindex->GetStakeModifierV1()));
        result.push_back(Pair("stakeModifier", stakeModifier));
        result.push_back(Pair("hashProofOfStake", hashProofOfStakeRet.GetHex()));
    }

    return result;
}

UniValue getblockcount(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getblockcount\n"
            "\nReturns the number of blocks in the longest block chain.\n"

            "\nResult:\n"
            "n    (numeric) The current block count\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockcount", "") + HelpExampleRpc("getblockcount", ""));

    LOCK(cs_main);
    return chainActive.Height();
}

UniValue getbestblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getbestblockhash\n"
            "\nReturns the hash of the best (tip) block in the longest block chain.\n"

            "\nResult\n"
            "\"hex\"      (string) the block hash hex encoded\n"

            "\nExamples\n" +
            HelpExampleCli("getbestblockhash", "") + HelpExampleRpc("getbestblockhash", ""));

    LOCK(cs_main);
    return chainActive.Tip()->GetBlockHash().GetHex();
}

void RPCNotifyBlockChange(bool fInitialDownload, const CBlockIndex* pindex)
{
    if(pindex) {
        std::lock_guard<std::mutex> lock(cs_blockchange);
        latestblock.hash = pindex->GetBlockHash();
        latestblock.height = pindex->nHeight;
    }
    cond_blockchange.notify_all();
}

UniValue waitfornewblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "waitfornewblock ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitfornewblock", "1000")
            + HelpExampleRpc("waitfornewblock", "1000")
        );
    int timeout = 0;
    if (params.size() > 0)
        timeout = params[0].get_int();
    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        block = latestblock;
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        else
            cond_blockchange.wait(lock, [&block]{return latestblock.height != block.height || latestblock.hash != block.hash || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblock blockhash ( timeout )\n"
            "\nWaits for a specific new block and returns useful info about it.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. \"blockhash\" (required, std::string) Block hash to wait for.\n"
            "2. timeout       (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
            + HelpExampleRpc("waitforblock", "\"0000000000079f8ef3d2c688c244eb7a4570b24c9ed7b4a8c619eb02596f8862\", 1000")
        );
    int timeout = 0;

    uint256 hash = uint256S(params[0].get_str());

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&hash]{return latestblock.hash == hash || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&hash]{return latestblock.hash == hash || !IsRPCRunning(); });
        block = latestblock;
    }

    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue waitforblockheight(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "waitforblockheight height ( timeout )\n"
            "\nWaits for (at least) block height and returns the height and hash\n"
            "of the current tip.\n"
            "\nReturns the current block on timeout or exit.\n"

            "\nArguments:\n"
            "1. height  (required, int) Block height to wait for (int)\n"
            "2. timeout (int, optional, default=0) Time in milliseconds to wait for a response. 0 indicates no timeout.\n"

            "\nResult:\n"
            "{                           (json object)\n"
            "  \"hash\" : {       (string) The blockhash\n"
            "  \"height\" : {     (int) Block height\n"
            "}\n"

            "\nExamples:\n"
            + HelpExampleCli("waitforblockheight", "\"100\", 1000")
            + HelpExampleRpc("waitforblockheight", "\"100\", 1000")
        );
    int timeout = 0;

    int height = params[0].get_int();

    if (params.size() > 1)
        timeout = params[1].get_int();

    CUpdatedBlock block;
    {
        std::unique_lock<std::mutex> lock(cs_blockchange);
        if(timeout)
            cond_blockchange.wait_for(lock, std::chrono::milliseconds(timeout), [&height]{return latestblock.height >= height || !IsRPCRunning();});
        else
            cond_blockchange.wait(lock, [&height]{return latestblock.height >= height || !IsRPCRunning(); });
        block = latestblock;
    }
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("hash", block.hash.GetHex()));
    ret.push_back(Pair("height", block.height));
    return ret;
}

UniValue getdifficulty(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getdifficulty\n"
            "\nReturns the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nResult:\n"
            "n.nnn       (numeric) the proof-of-work difficulty as a multiple of the minimum difficulty.\n"

            "\nExamples:\n" +
            HelpExampleCli("getdifficulty", "") + HelpExampleRpc("getdifficulty", ""));

    LOCK(cs_main);
    return GetDifficulty();
}


UniValue mempoolToJSON(bool fVerbose = false)
{
    if (fVerbose) {
        LOCK(mempool.cs);
        UniValue o(UniValue::VOBJ);
        for (const PAIRTYPE(uint256, CTxMemPoolEntry) & entry : mempool.mapTx) {
            const uint256& hash = entry.first;
            const CTxMemPoolEntry& e = entry.second;
            UniValue info(UniValue::VOBJ);
            info.push_back(Pair("size", (int)e.GetTxSize()));
            info.push_back(Pair("fee", ValueFromAmount(e.GetFee())));
            info.push_back(Pair("time", e.GetTime()));
            info.push_back(Pair("height", (int)e.GetHeight()));
            info.push_back(Pair("startingpriority", e.GetPriority(e.GetHeight())));
            info.push_back(Pair("currentpriority", e.GetPriority(chainActive.Height())));
            const CTransaction& tx = e.GetTx();
            std::set<std::string> setDepends;
            for (const CTxIn& txin : tx.vin) {
                if (mempool.exists(txin.prevout.hash))
                    setDepends.insert(txin.prevout.hash.ToString());
            }

            UniValue depends(UniValue::VARR);
            for (const std::string& dep : setDepends) {
                depends.push_back(dep);
            }

            info.push_back(Pair("depends", depends));
            o.push_back(Pair(hash.ToString(), info));
        }
        return o;
    } else {
        std::vector<uint256> vtxid;
        mempool.queryHashes(vtxid);

        UniValue a(UniValue::VARR);
        for (const uint256& hash : vtxid)
            a.push_back(hash.ToString());

        return a;
    }
}

UniValue getrawmempool(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "getrawmempool ( verbose )\n"
            "\nReturns all transaction ids in memory pool as a json array of string transaction ids.\n"

            "\nArguments:\n"
            "1. verbose           (boolean, optional, default=false) true for a json object, false for array of transaction ids\n"

            "\nResult: (for verbose = false):\n"
            "[                     (json array of string)\n"
            "  \"transactionid\"     (string) The transaction id\n"
            "  ,...\n"
            "]\n"

            "\nResult: (for verbose = true):\n"
            "{                           (json object)\n"
            "  \"transactionid\" : {       (json object)\n"
            "    \"size\" : n,             (numeric) transaction size in bytes\n"
            "    \"fee\" : n,              (numeric) transaction fee in WAGE\n"
            "    \"time\" : n,             (numeric) local time transaction entered pool in seconds since 1 Jan 1970 GMT\n"
            "    \"height\" : n,           (numeric) block height when transaction entered pool\n"
            "    \"startingpriority\" : n, (numeric) priority when transaction entered pool\n"
            "    \"currentpriority\" : n,  (numeric) transaction priority now\n"
            "    \"depends\" : [           (array) unconfirmed transactions used as inputs for this transaction\n"
            "        \"transactionid\",    (string) parent transaction id\n"
            "       ... ]\n"
            "  }, ...\n"
            "]\n"

            "\nExamples\n" +
            HelpExampleCli("getrawmempool", "true") + HelpExampleRpc("getrawmempool", "true"));

    LOCK(cs_main);

    bool fVerbose = false;
    if (params.size() > 0)
        fVerbose = params[0].get_bool();

    return mempoolToJSON(fVerbose);
}

UniValue getblockhash(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getblockhash index\n"
            "\nReturns hash of block in best-block-chain at index provided.\n"

            "\nArguments:\n"
            "1. index         (numeric, required) The block index\n"

            "\nResult:\n"
            "\"hash\"         (string) The block hash\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockhash", "1000") + HelpExampleRpc("getblockhash", "1000"));

    LOCK(cs_main);

    int nHeight = params[0].get_int();
    if (nHeight < 0 || nHeight > chainActive.Height())
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Block height out of range");

    CBlockIndex* pblockindex = chainActive[nHeight];
    return pblockindex->GetBlockHash().GetHex();
}

//UniValue getblock(const UniValue& params, bool fHelp)
UniValue getblock(const JSONRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "getblock \"blockhash\" ( verbosity )\n"
            "\nIf verbosity is 0, returns a string that is serialized, hex-encoded data for block 'hash'.\n"
            "If verbosity is 1, returns an Object with information about block <hash>.\n"
            "If verbosity is 2, returns an Object with information about block <hash> and information about each transaction.\n"

            "\nArguments:\n"
            "1. \"blockhash\"            (string, required) The block hash\n"
            "2. verbosity              (numeric, optional, default=1) 0 for hex encoded data, 1 for a json object, and 2 for json object with transaction data\n"

            "\nResult (for verbosity = 0):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash'.\n"

            "\nResult (for verbosity = 1):\n"
            "{\n"
            "  \"hash\" : \"hash\",     (string) the block hash (same as provided)\n"
            "  \"confirmations\" : n,   (numeric) The number of confirmations, or -1 if the block is not on the main chain\n"
            "  \"size\" : n,            (numeric) The block size\n"
            "  \"height\" : n,          (numeric) The block height or index\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"tx\" : [               (array of string) The transaction ids\n"
            "     \"transactionid\"     (string) The transaction id\n"
            "     ,...\n"
            "  ],\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "  \"difficulty\" : x.xxx,  (numeric) The difficulty\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"nextblockhash\" : \"hash\"       (string) The hash of the next block\n"
            "  \"stakeModifier\" : \"xxx\",       (string) Proof of Stake modifier\n"
            "  \"hashProofOfStake\" : \"hash\",   (string) Proof of Stake hash\n"
            "  }\n"
            "}\n"

                        "\nResult (for verbosity = 2):\n"
             "{\n"
             "  ...,                     Same output as verbosity = 1.\n"
             "  \"tx\" : [               (array of Objects) The transactions in the format of the getrawtransaction RPC. Different from verbosity = 1 \"tx\" result.\n"
             "         ,...\n"
             "  ],\n"
             "  ,...                     Same output as verbosity = 1.\n"
             "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblock", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    LOCK(cs_main);

   /* std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));*/
    uint256 hash(ParseHashV(request.params[0], "blockhash"));

    int verbosity = 1;
     if (!request.params[1].isNull()) {
         if(request.params[1].isNum())
             verbosity = request.params[1].get_int();
         else
             verbosity = request.params[1].get_bool() ? 1 : 0;
     }

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlock block;
    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!ReadBlockFromDisk(block, pblockindex))
        throw JSONRPCError(RPC_INTERNAL_ERROR, "Can't read block from disk");

    if (verbosity <= 0) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << block;
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockToJSON(block, pblockindex, verbosity >= 2);
}

UniValue getblockheader(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw std::runtime_error(
            "getblockheader \"hash\" ( verbose )\n"
            "\nIf verbose is false, returns a string that is serialized, hex-encoded data for block 'hash' header.\n"
            "If verbose is true, returns an Object with information about block <hash> header.\n"

            "\nArguments:\n"
            "1. \"hash\"          (string, required) The block hash\n"
            "2. verbose           (boolean, optional, default=true) true for a json object, false for the hex encoded data\n"

            "\nResult (for verbose = true):\n"
            "{\n"
            "  \"version\" : n,         (numeric) The block version\n"
            "  \"previousblockhash\" : \"hash\",  (string) The hash of the previous block\n"
            "  \"merkleroot\" : \"xxxx\", (string) The merkle root\n"
            "  \"time\" : ttt,          (numeric) The block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"mediantime\" : ttt,    (numeric) The median block time in seconds since epoch (Jan 1 1970 GMT)\n"
            "  \"nonce\" : n,           (numeric) The nonce\n"
            "  \"bits\" : \"1d00ffff\", (string) The bits\n"
            "}\n"

            "\nResult (for verbose=false):\n"
            "\"data\"             (string) A string that is serialized, hex-encoded data for block 'hash' header.\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\"") +
            HelpExampleRpc("getblockheader", "\"00000000000fd08c2fb661d2fcb0d49abb3a91e5f27082ce64feed3b4dede2e2\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));

    bool fVerbose = true;
    if (params.size() > 1)
        fVerbose = params[1].get_bool();

    if (mapBlockIndex.count(hash) == 0)
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

    CBlockIndex* pblockindex = mapBlockIndex[hash];

    if (!fVerbose) {
        CDataStream ssBlock(SER_NETWORK, PROTOCOL_VERSION);
        ssBlock << pblockindex->GetBlockHeader();
        std::string strHex = HexStr(ssBlock.begin(), ssBlock.end());
        return strHex;
    }

    return blockheaderToJSON(pblockindex);
}

UniValue gettxoutsetinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "gettxoutsetinfo\n"
            "\nReturns statistics about the unspent transaction output set.\n"
            "Note this call may take some time.\n"

            "\nResult:\n"
            "{\n"
            "  \"height\":n,     (numeric) The current block height (index)\n"
            "  \"bestblock\": \"hex\",   (string) the best block hash hex\n"
            "  \"transactions\": n,      (numeric) The number of transactions\n"
            "  \"txouts\": n,            (numeric) The number of output transactions\n"
            "  \"bytes_serialized\": n,  (numeric) The serialized size\n"
            "  \"hash_serialized\": \"hash\",   (string) The serialized hash\n"
            "  \"total_amount\": x.xxx          (numeric) The total amount\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("gettxoutsetinfo", "") + HelpExampleRpc("gettxoutsetinfo", ""));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    CCoinsStats stats;
    FlushStateToDisk();
    if (pcoinsTip->GetStats(stats)) {
        ret.push_back(Pair("height", (int64_t)stats.nHeight));
        ret.push_back(Pair("bestblock", stats.hashBlock.GetHex()));
        ret.push_back(Pair("transactions", (int64_t)stats.nTransactions));
        ret.push_back(Pair("txouts", (int64_t)stats.nTransactionOutputs));
        ret.push_back(Pair("bytes_serialized", (int64_t)stats.nSerializedSize));
        ret.push_back(Pair("hash_serialized", stats.hashSerialized.GetHex()));
        ret.push_back(Pair("total_amount", ValueFromAmount(stats.nTotalAmount)));
    }
    return ret;
}

UniValue gettxout(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
            "gettxout \"txid\" n ( includemempool )\n"
            "\nReturns details about an unspent transaction output.\n"

            "\nArguments:\n"
            "1. \"txid\"       (string, required) The transaction id\n"
            "2. n              (numeric, required) vout value\n"
            "3. includemempool  (boolean, optional) Whether to included the mem pool\n"

            "\nResult:\n"
            "{\n"
            "  \"bestblock\" : \"hash\",    (string) the block hash\n"
            "  \"confirmations\" : n,       (numeric) The number of confirmations\n"
            "  \"value\" : x.xxx,           (numeric) The transaction value in btc\n"
            "  \"scriptPubKey\" : {         (json object)\n"
            "     \"asm\" : \"code\",       (string) \n"
            "     \"hex\" : \"hex\",        (string) \n"
            "     \"reqSigs\" : n,          (numeric) Number of required signatures\n"
            "     \"type\" : \"pubkeyhash\", (string) The type, eg pubkeyhash\n"
            "     \"addresses\" : [          (array of string) array of DIGIWAGE addresses\n"
            "     \"address\"            (string) DIGIWAGE address\n"
            "        ,...\n"
            "     ]\n"
            "  },\n"
            "  \"version\" : n,            (numeric) The version\n"
            "  \"coinbase\" : true|false   (boolean) Coinbase or not\n"
            "}\n"

            "\nExamples:\n"
            "\nGet unspent transactions\n" +
            HelpExampleCli("listunspent", "") +
            "\nView the details\n" +
            HelpExampleCli("gettxout", "\"txid\" 1") +
            "\nAs a json rpc call\n" +
            HelpExampleRpc("gettxout", "\"txid\", 1"));

    LOCK(cs_main);

    UniValue ret(UniValue::VOBJ);

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    int n = params[1].get_int();
    bool fMempool = true;
    if (params.size() > 2)
        fMempool = params[2].get_bool();

    CCoins coins;
    if (fMempool) {
        LOCK(mempool.cs);
        CCoinsViewMemPool view(pcoinsTip, mempool);
        if (!view.GetCoins(hash, coins))
            return NullUniValue;
        mempool.pruneSpent(hash, coins); // TODO: this should be done by the CCoinsViewMemPool
    } else {
        if (!pcoinsTip->GetCoins(hash, coins))
            return NullUniValue;
    }
    if (n < 0 || (unsigned int)n >= coins.vout.size() || coins.vout[n].IsNull())
        return NullUniValue;

    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    CBlockIndex* pindex = it->second;
    ret.push_back(Pair("bestblock", pindex->GetBlockHash().GetHex()));
    if ((unsigned int)coins.nHeight == MEMPOOL_HEIGHT)
        ret.push_back(Pair("confirmations", 0));
    else
        ret.push_back(Pair("confirmations", pindex->nHeight - coins.nHeight + 1));
    ret.push_back(Pair("value", ValueFromAmount(coins.vout[n].nValue)));
    UniValue o(UniValue::VOBJ);
    ScriptPubKeyToJSON(coins.vout[n].scriptPubKey, o, true);
    ret.push_back(Pair("scriptPubKey", o));
    ret.push_back(Pair("version", coins.nVersion));
    ret.push_back(Pair("coinbase", coins.fCoinBase));

    return ret;
}

UniValue verifychain(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw std::runtime_error(
            "verifychain ( numblocks )\n"
            "\nVerifies blockchain database.\n"

            "\nArguments:\n"
            "1. numblocks    (numeric, optional, default=288, 0=all) The number of blocks to check.\n"

            "\nResult:\n"
            "true|false       (boolean) Verified or not\n"

            "\nExamples:\n" +
            HelpExampleCli("verifychain", "") + HelpExampleRpc("verifychain", ""));

    LOCK(cs_main);

    int nCheckLevel = 4;
    int nCheckDepth = GetArg("-checkblocks", 288);
    if (params.size() > 0)
        nCheckDepth = params[0].get_int();

    fVerifyingBlocks = true;
    bool fVerified = CVerifyDB().VerifyDB(pcoinsTip, nCheckLevel, nCheckDepth);
    fVerifyingBlocks = false;

    return fVerified;
}

/** Implementation of IsSuperMajority with better feedback */
static UniValue SoftForkMajorityDesc(int version, CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    UniValue rv(UniValue::VOBJ);
    bool activated = false;
    switch(version) {
    case 1:
    case 2:
    case 3:
        activated = pindex->nHeight >= 1;
        break;
    case 4:
        activated = pindex->nHeight >= consensusParams.height_start_ZC;
        break;
    case 5:
        activated = pindex->nHeight >= consensusParams.height_RHF;
        break;
    }
    rv.push_back(Pair("status", activated));
    return rv;
}
static UniValue SoftForkDesc(const std::string &name, int version, CBlockIndex* pindex)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    UniValue rv(UniValue::VOBJ);
    rv.push_back(Pair("id", name));
    rv.push_back(Pair("version", version));
    rv.push_back(Pair("reject", SoftForkMajorityDesc(version, pindex, consensus)));
    return rv;
}

UniValue getblockchaininfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getblockchaininfo\n"
            "Returns an object containing various state info regarding block chain processing.\n"

            "\nResult:\n"
            "{\n"
            "  \"chain\": \"xxxx\",        (string) current network name as defined in BIP70 (main, test, regtest)\n"
            "  \"blocks\": xxxxxx,         (numeric) the current number of blocks processed in the server\n"
            "  \"headers\": xxxxxx,        (numeric) the current number of headers we have validated\n"
            "  \"bestblockhash\": \"...\", (string) the hash of the currently best block\n"
            "  \"difficulty\": xxxxxx,     (numeric) the current difficulty\n"
            "  \"verificationprogress\": xxxx, (numeric) estimate of verification progress [0..1]\n"
            "  \"chainwork\": \"xxxx\"     (string) total amount of work in active chain, in hexadecimal\n"
            "  \"supply\" : \"supply\"        (numeric) The total amount of WAGE in existence\n"
            "  \"burned\" : \"supply\"        (numeric) The total amount of WAGE burned (In fees and unspendable outputs)\n"
            "  \"softforks\": [            (array) status of softforks in progress\n"
            "     {\n"
            "        \"id\": \"xxxx\",        (string) name of softfork\n"
            "        \"version\": xx,         (numeric) block version\n"
            "        \"reject\": {            (object) progress toward rejecting pre-softfork blocks\n"
            "           \"status\": xx,       (boolean) true if threshold reached\n"
            "        },\n"
            "     }, ...\n"
            "  ]\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getblockchaininfo", "") + HelpExampleRpc("getblockchaininfo", ""));

    LOCK(cs_main);

    UniValue obj(UniValue::VOBJ);
    obj.push_back(Pair("chain", Params().NetworkIDString()));
    obj.push_back(Pair("blocks", (int)chainActive.Height()));
    obj.push_back(Pair("headers", pindexBestHeader ? pindexBestHeader->nHeight : -1));
    obj.push_back(Pair("bestblockhash", chainActive.Tip()->GetBlockHash().GetHex()));
    obj.push_back(Pair("difficulty", (double)GetDifficulty()));
    obj.push_back(Pair("verificationprogress", Checkpoints::GuessVerificationProgress(chainActive.Tip())));
    obj.push_back(Pair("chainwork", chainActive.Tip()->nChainWork.GetHex()));
    obj.push_back(Pair("moneysupply", ValueFromAmount(chainActive.Tip()->nMoneySupply)));
    obj.push_back(Pair("burned", ValueFromAmount(nBurnedCoins)));
    CBlockIndex* tip = chainActive.Tip();
    UniValue softforks(UniValue::VARR);
    softforks.push_back(SoftForkDesc("bip65", 5, tip));
    obj.push_back(Pair("softforks",             softforks));
    return obj;
}

/** Comparison function for sorting the getchaintips heads.  */
struct CompareBlocksByHeight {
    bool operator()(const CBlockIndex* a, const CBlockIndex* b) const
    {
        /* Make sure that unequal blocks with the same height do not compare
           equal. Use the pointers themselves to make a distinction. */

        if (a->nHeight != b->nHeight)
            return (a->nHeight > b->nHeight);

        return a < b;
    }
};

UniValue getchaintips(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getchaintips\n"
            "Return information about all known tips in the block tree,"
            " including the main chain as well as orphaned branches.\n"

            "\nResult:\n"
            "[\n"
            "  {\n"
            "    \"height\": xxxx,         (numeric) height of the chain tip\n"
            "    \"hash\": \"xxxx\",         (string) block hash of the tip\n"
            "    \"branchlen\": 0          (numeric) zero for main chain\n"
            "    \"status\": \"active\"      (string) \"active\" for the main chain\n"
            "  },\n"
            "  {\n"
            "    \"height\": xxxx,\n"
            "    \"hash\": \"xxxx\",\n"
            "    \"branchlen\": 1          (numeric) length of branch connecting the tip to the main chain\n"
            "    \"status\": \"xxxx\"        (string) status of the chain (active, valid-fork, valid-headers, headers-only, invalid)\n"
            "  }\n"
            "]\n"

            "Possible values for status:\n"
            "1.  \"invalid\"               This branch contains at least one invalid block\n"
            "2.  \"headers-only\"          Not all blocks for this branch are available, but the headers are valid\n"
            "3.  \"valid-headers\"         All blocks are available for this branch, but they were never fully validated\n"
            "4.  \"valid-fork\"            This branch is not part of the active chain, but is fully validated\n"
            "5.  \"active\"                This is the tip of the active main chain, which is certainly valid\n"

            "\nExamples:\n" +
            HelpExampleCli("getchaintips", "") + HelpExampleRpc("getchaintips", ""));

    LOCK(cs_main);

    /* Build up a list of chain tips.  We start with the list of all
       known blocks, and successively remove blocks that appear as pprev
       of another block.  */
    std::set<const CBlockIndex*, CompareBlocksByHeight> setTips;
    for (const PAIRTYPE(const uint256, CBlockIndex*) & item : mapBlockIndex)
        setTips.insert(item.second);
    for (const PAIRTYPE(const uint256, CBlockIndex*) & item : mapBlockIndex) {
        const CBlockIndex* pprev = item.second->pprev;
        if (pprev)
            setTips.erase(pprev);
    }

    // Always report the currently active tip.
    setTips.insert(chainActive.Tip());

    /* Construct the output array.  */
    UniValue res(UniValue::VARR);
    for (const CBlockIndex* block : setTips) {
        UniValue obj(UniValue::VOBJ);
        obj.push_back(Pair("height", block->nHeight));
        obj.push_back(Pair("hash", block->phashBlock->GetHex()));

        const int branchLen = block->nHeight - chainActive.FindFork(block)->nHeight;
        obj.push_back(Pair("branchlen", branchLen));

        std::string status;
        if (chainActive.Contains(block)) {
            // This block is part of the currently active chain.
            status = "active";
        } else if (block->nStatus & BLOCK_FAILED_MASK) {
            // This block or one of its ancestors is invalid.
            status = "invalid";
        } else if (block->nChainTx == 0) {
            // This block cannot be connected because full block data for it or one of its parents is missing.
            status = "headers-only";
        } else if (block->IsValid(BLOCK_VALID_SCRIPTS)) {
            // This block is fully validated, but no longer part of the active chain. It was probably the active block once, but was reorganized.
            status = "valid-fork";
        } else if (block->IsValid(BLOCK_VALID_TREE)) {
            // The headers for this block are valid, but it has not been validated. It was probably never part of the most-work chain.
            status = "valid-headers";
        } else {
            // No clue.
            status = "unknown";
        }
        obj.push_back(Pair("status", status));

        res.push_back(obj);
    }

    return res;
}

UniValue getfeeinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "getfeeinfo blocks\n"
            "\nReturns details of transaction fees over the last n blocks.\n"

            "\nArguments:\n"
            "1. blocks     (int, required) the number of blocks to get transaction data from\n"

            "\nResult:\n"
            "{\n"
            "  \"txcount\": xxxxx                (numeric) Current tx count\n"
            "  \"txbytes\": xxxxx                (numeric) Sum of all tx sizes\n"
            "  \"ttlfee\": xxxxx                 (numeric) Sum of all fees\n"
            "  \"feeperkb\": xxxxx               (numeric) Average fee per kb over the block range\n"
            "  \"rec_highpriorityfee_perkb\": xxxxx    (numeric) Recommended fee per kb to use for a high priority tx\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getfeeinfo", "5") + HelpExampleRpc("getfeeinfo", "5"));

    int nBlocks = params[0].get_int();
    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }
    int nStartHeight = nBestHeight - nBlocks;
    if (nBlocks < 0 || nStartHeight <= 0)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid start height");

    UniValue newParams(UniValue::VARR);
    newParams.push_back(UniValue(nStartHeight));
    newParams.push_back(UniValue(nBlocks));
    newParams.push_back(UniValue(true));    // fFeeOnly

    return getblockindexstats(newParams, false);
}

UniValue mempoolInfoToJSON()
{
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("size", (int64_t) mempool.size()));
    ret.push_back(Pair("bytes", (int64_t) mempool.GetTotalTxSize()));
    //ret.push_back(Pair("usage", (int64_t) mempool.DynamicMemoryUsage()));

    return ret;
}

UniValue getmempoolinfo(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 0)
        throw std::runtime_error(
            "getmempoolinfo\n"
            "\nReturns details on the active state of the TX memory pool.\n"

            "\nResult:\n"
            "{\n"
            "  \"size\": xxxxx                (numeric) Current tx count\n"
            "  \"bytes\": xxxxx               (numeric) Sum of all tx sizes\n"
            "}\n"

            "\nExamples:\n" +
            HelpExampleCli("getmempoolinfo", "") + HelpExampleRpc("getmempoolinfo", ""));

    return mempoolInfoToJSON();
}

UniValue invalidateblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "invalidateblock \"hash\"\n"
            "\nPermanently marks a block as invalid, as if it violated a consensus rule.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to mark as invalid\n"

            "\nExamples:\n" +
            HelpExampleCli("invalidateblock", "\"blockhash\"") + HelpExampleRpc("invalidateblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        InvalidateBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

UniValue reconsiderblock(const UniValue& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw std::runtime_error(
            "reconsiderblock \"hash\"\n"
            "\nRemoves invalidity status of a block and its descendants, reconsider them for activation.\n"
            "This can be used to undo the effects of invalidateblock.\n"

            "\nArguments:\n"
            "1. hash   (string, required) the hash of the block to reconsider\n"

            "\nExamples:\n" +
            HelpExampleCli("reconsiderblock", "\"blockhash\"") + HelpExampleRpc("reconsiderblock", "\"blockhash\""));

    std::string strHash = params[0].get_str();
    uint256 hash(uint256S(strHash));
    CValidationState state;

    {
        LOCK(cs_main);
        if (mapBlockIndex.count(hash) == 0)
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Block not found");

        CBlockIndex* pblockindex = mapBlockIndex[hash];
        ReconsiderBlock(state, pblockindex);
    }

    if (state.IsValid()) {
        ActivateBestChain(state);
    }

    if (!state.IsValid()) {
        throw JSONRPCError(RPC_DATABASE_ERROR, state.GetRejectReason());
    }

    return NullUniValue;
}

void validaterange(const UniValue& params, int& heightStart, int& heightEnd, int minHeightStart)
{
    if (params.size() < 2) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Not enough parameters in validaterange");
    }

    int nBestHeight;
    {
        LOCK(cs_main);
        nBestHeight = chainActive.Height();
    }

    heightStart = params[0].get_int();
    if (heightStart > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid starting block (%d). Out of range.", heightStart));
    }

    const int range = params[1].get_int();
    if (range < 1) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid block range. Must be strictly positive.");
    }

    heightEnd = heightStart + range - 1;

    if (heightStart < minHeightStart && heightEnd >= minHeightStart) {
        heightStart = minHeightStart;
    }

    if (heightEnd > nBestHeight) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Invalid ending block (%d). Out of range.", heightEnd));
    }
}

UniValue getblockindexstats(const UniValue& params, bool fHelp) {
    if (fHelp || params.size() < 2 || params.size() > 3)
        throw std::runtime_error(
                "getblockindexstats height range ( fFeeOnly )\n"
                "\nReturns aggregated BlockIndex data for blocks "
                "\n[height, height+1, height+2, ..., height+range-1]\n"

                "\nArguments:\n"
                "1. height             (numeric, required) block height where the search starts.\n"
                "2. range              (numeric, required) number of blocks to include.\n"
                "3. fFeeOnly           (boolean, optional, default=False) return only fee info.\n"

                "\nResult:\n"
                "{\n"
                "  \"first_block\": \"x\"            (integer) First counted block\n"
                "  \"last_block\": \"x\"             (integer) Last counted block\n"
                "  \"txcount\": xxxxx                (numeric) tx count (excluding coinbase/coinstake)\n"
                "  \"txcount_all\": xxxxx            (numeric) tx count (including coinbase/coinstake)\n"
                "  \"spendcount\": {             [if fFeeOnly=False]\n"
                "        \"denom_1\": xxxx           (numeric) number of spends of denom_1 occurred over the block range\n"
                "        \"denom_5\": xxxx           (numeric) number of spends of denom_5 occurred over the block range\n"
                "         ...                    ... number of spends of other denominations: ..., 10, 50, 100, 500, 1000, 5000\n"
                "  }\n"
                "  \"txbytes\": xxxxx                (numeric) Sum of the size of all txes (zWAGE excluded) over block range\n"
                "  \"ttlfee\": xxxxx                 (numeric) Sum of the fee amount of all txes (zWAGE mints excluded) over block range\n"
                "  \"ttlfee_all\": xxxxx             (numeric) Sum of the fee amount of all txes (zWAGE mints included) over block range\n"
                "  \"feeperkb\": xxxxx               (numeric) Average fee per kb (excluding ZC TXes)\n"
                "}\n"

                "\nExamples:\n" +
                HelpExampleCli("getblockindexstats", "1200000 1000") +
                HelpExampleRpc("getblockindexstats", "1200000, 1000"));

    int heightStart, heightEnd;
    validaterange(params, heightStart, heightEnd);
    // return object
    UniValue ret(UniValue::VOBJ);
    ret.push_back(Pair("Starting block", heightStart));
    ret.push_back(Pair("Ending block", heightEnd));

    bool fFeeOnly = false;
    if (params.size() > 2) {
        fFeeOnly = params[2].get_bool();
    }

    CAmount nFees = 0;
    CAmount nFees_all = 0;
    int64_t nBytes = 0;
    int64_t nTxCount = 0;
    int64_t nTxCount_all = 0;

    std::map<libzerocoin::CoinDenomination, int64_t> mapSpendCount;
    for (auto& denom : libzerocoin::zerocoinDenomList) {
        mapSpendCount.insert(std::make_pair(denom, 0));
    }

    CBlockIndex* pindex = nullptr;
    {
        LOCK(cs_main);
        pindex = chainActive[heightStart];
    }

    if (!pindex)
        throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid block height");

    while (true) {
        CBlock block;
        if (!ReadBlockFromDisk(block, pindex)) {
            throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read block from disk");
        }

        CAmount nValueIn = 0;
        CAmount nValueOut = 0;
        const int ntx = block.vtx.size();
        nTxCount_all += ntx;
        nTxCount = block.IsProofOfStake() ? nTxCount + ntx - 2 : nTxCount + ntx - 1;

        // loop through each tx in block and save size and fee
        for (const CTransaction& tx : block.vtx) {
            if (tx.IsCoinBase() || (tx.IsCoinStake() && !tx.HasZerocoinSpendInputs()))
                continue;

            // fetch input value from prevouts and count spends
            for (unsigned int j = 0; j < tx.vin.size(); j++) {
                if (tx.vin[j].IsZerocoinSpend()) {
                    if (!fFeeOnly)
                        mapSpendCount[libzerocoin::IntToZerocoinDenomination(tx.vin[j].nSequence)]++;
                    continue;
                }

                COutPoint prevout = tx.vin[j].prevout;
                CTransaction txPrev;
                uint256 hashBlock;
                if(!GetTransaction(prevout.hash, txPrev, hashBlock, true))
                    throw JSONRPCError(RPC_DATABASE_ERROR, "failed to read tx from disk");
                nValueIn += txPrev.vout[prevout.n].nValue;
            }

            // zc spends have no fee
            if (tx.HasZerocoinSpendInputs())
                continue;

            // sum output values in nValueOut
            for (unsigned int j = 0; j < tx.vout.size(); j++) {
                nValueOut += tx.vout[j].nValue;
            }

            // update sums
            nFees_all += nValueIn - nValueOut;
            if (!tx.HasZerocoinMintOutputs()) {
                nFees += nValueIn - nValueOut;
                nBytes += tx.GetSerializeSize(SER_NETWORK, CLIENT_VERSION);
            }
        }

        if (pindex->nHeight < heightEnd) {
            LOCK(cs_main);
            pindex = chainActive.Next(pindex);
        } else {
            break;
        }
    }

    // get fee rate
    CFeeRate nFeeRate = CFeeRate(nFees, nBytes);

    // return UniValue object
    ret.push_back(Pair("txcount", (int64_t)nTxCount));
    ret.push_back(Pair("txcount_all", (int64_t)nTxCount_all));
    if (!fFeeOnly) {
        UniValue mint_obj(UniValue::VOBJ);
        UniValue spend_obj(UniValue::VOBJ);
        for (auto& denom : libzerocoin::zerocoinDenomList) {
            spend_obj.push_back(Pair(strprintf("denom_%d", ZerocoinDenominationToInt(denom)), mapSpendCount[denom]));
        }
        ret.push_back(Pair("spendcount", spend_obj));
    }
    ret.push_back(Pair("txbytes", (int64_t)nBytes));
    ret.push_back(Pair("ttlfee", FormatMoney(nFees)));
    ret.push_back(Pair("ttlfee_all", FormatMoney(nFees_all)));
    ret.push_back(Pair("feeperkb", FormatMoney(nFeeRate.GetFeePerK())));

    return ret;

}

//! Search for a given set of pubkey scripts
bool FindScriptPubKey(std::atomic<int>& scan_progress, const std::atomic<bool>& should_abort, int64_t& count, CCoinsViewCursor* cursor, const std::set<CScript>& needles, std::map<COutPoint, Coin>& out_results) {
    scan_progress = 0;
    count = 0;
    while (cursor->Valid()) {
        COutPoint key;
        Coin coin;
        if (!cursor->GetKey(key) || !cursor->GetValue(coin)) return false;
        if (++count % 8192 == 0) {
            boost::this_thread::interruption_point();
            if (should_abort) {
                // allow to abort the scan via the abort reference
                return false;
            }
        }
        if (count % 256 == 0) {
            // update progress reference every 256 item
            uint32_t high = 0x100 * *key.hash.begin() + *(key.hash.begin() + 1);
            scan_progress = (int)(high * 100.0 / 65536.0 + 0.5);
        }
        if (needles.count(coin.out.scriptPubKey)) {
            out_results.emplace(key, coin);
        }
        cursor->Next();
    }
    scan_progress = 100;
    return true;
}

/** RAII object to prevent concurrency issue when scanning the txout set */
static std::mutex g_utxosetscan;
static std::atomic<int> g_scan_progress;
static std::atomic<bool> g_scan_in_progress;
static std::atomic<bool> g_should_abort_scan;
class CoinsViewScanReserver
{
private:
    bool m_could_reserve;
public:
    explicit CoinsViewScanReserver() : m_could_reserve(false) {}

    bool reserve() {
        assert (!m_could_reserve);
        std::lock_guard<std::mutex> lock(g_utxosetscan);
        if (g_scan_in_progress) {
            return false;
        }
        g_scan_in_progress = true;
        m_could_reserve = true;
        return true;
    }

    ~CoinsViewScanReserver() {
        if (m_could_reserve) {
            std::lock_guard<std::mutex> lock(g_utxosetscan);
            g_scan_in_progress = false;
        }
    }
};

UniValue scantxoutset(const JSONRequest& request)
{
    if (request.fHelp || request.params.size() < 1 || request.params.size() > 2)
        throw std::runtime_error(
            "scantxoutset <action> ( <scanobjects> )\n"
            "\nEXPERIMENTAL warning: this call may be removed or changed in future releases.\n"
            "\nScans the unspent transaction output set for entries that match certain output descriptors.\n"
            "Examples of output descriptors are:\n"
            "    addr(<address>)                      Outputs whose scriptPubKey corresponds to the specified address (does not include P2PK)\n"
            "    raw(<hex script>)                    Outputs whose scriptPubKey equals the specified hex scripts\n"
            "    combo(<pubkey>)                      P2PK and P2PKH outputs for the given pubkey\n"
            "    pkh(<pubkey>)                        P2PKH outputs for the given pubkey\n"
            "    sh(multi(<n>,<pubkey>,<pubkey>,...)) P2SH-multisig outputs for the given threshold and pubkeys\n"
            "\nIn the above, <pubkey> either refers to a fixed public key in hexadecimal notation, or to an DRKV/DRKP optionally followed by one\n"
            "or more path elements separated by \"/\", and optionally ending in \"/*\" (unhardened), or \"/*'\" or \"/*h\" (hardened) to specify all\n"
            "unhardened or hardened child keys.\n"
            "In the latter case, a range needs to be specified by below if different from 1000.\n"
            "For more information on output descriptors, see the documentation in the doc/descriptors.md file.\n"
            "\nArguments:\n"
            "1. \"action\"                       (string, required) The action to execute\n"
            "                                      \"start\" for starting a scan\n"
            "                                      \"abort\" for aborting the current scan (returns true when abort was successful)\n"
            "                                      \"status\" for progress report (in %) of the current scan\n"
            "2. \"scanobjects\"                  (array, required) Array of scan objects\n"
            "    [                             Every scan object is either a string descriptor or an object:\n"
            "        \"descriptor\",             (string, optional) An output descriptor\n"
            "        {                         (object, optional) An object with output descriptor and metadata\n"
            "          \"desc\": \"descriptor\",   (string, required) An output descriptor\n"
            "          \"range\": n,             (numeric, optional) Up to what child index HD chains should be explored (default: 1000)\n"
            "        },\n"
            "        ...\n"
            "    ]\n"
            "\nResult:\n"
            "{\n"
            "  \"unspents\": [\n"
            "    {\n"
            "    \"txid\" : \"transactionid\",     (string) The transaction id\n"
            "    \"vout\": n,                    (numeric) the vout value\n"
            "    \"scriptPubKey\" : \"script\",    (string) the script key\n"
            "    \"amount\" : x.xxx,             (numeric) The total amount in " + CURRENCY_UNIT + " of the unspent output\n"
            "    \"height\" : n,                 (numeric) Height of the unspent transaction output\n"
            "   }\n"
            "   ,...], \n"
            " \"total_amount\" : x.xxx,          (numeric) The total amount of all found unspent outputs in " + CURRENCY_UNIT + "\n"
            "]\n"
        );

    RPCTypeCheck(request.params, {UniValue::VSTR, UniValue::VARR});

    UniValue result(UniValue::VOBJ);
    if (request.params[0].get_str() == "status") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // no scan in progress
            return NullUniValue;
        }
        result.pushKV("progress", g_scan_progress);
        return result;
    } else if (request.params[0].get_str() == "abort") {
        CoinsViewScanReserver reserver;
        if (reserver.reserve()) {
            // reserve was possible which means no scan was running
            return false;
        }
        // set the abort flag
        g_should_abort_scan = true;
        return true;
    } else if (request.params[0].get_str() == "start") {
        CoinsViewScanReserver reserver;
        if (!reserver.reserve()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan already in progress, use action \"abort\" or \"status\"");
        }
        std::set<CScript> needles;
        CAmount total_in = 0;

        // loop through the scan objects
        for (const UniValue& scanobject : request.params[1].get_array().getValues()) {
            std::string desc_str;
            int range = 1000;
            if (scanobject.isStr()) {
                desc_str = scanobject.get_str();
            } else if (scanobject.isObject()) {
                UniValue desc_uni = find_value(scanobject, "desc");
                if (desc_uni.isNull()) throw JSONRPCError(RPC_INVALID_PARAMETER, "Descriptor needs to be provided in scan object");
                desc_str = desc_uni.get_str();
                UniValue range_uni = find_value(scanobject, "range");
                if (!range_uni.isNull()) {
                    range = range_uni.get_int();
                    if (range < 0 || range > 1000000) throw JSONRPCError(RPC_INVALID_PARAMETER, "range out of range");
                }
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Scan object needs to be either a string or an object");
            }

            FlatSigningProvider provider;
            auto desc = Parse(desc_str, provider);
            if (!desc) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Invalid descriptor '%s'", desc_str));
            }
            if (!desc->IsRange()) range = 0;
            for (int i = 0; i <= range; ++i) {
                std::vector<CScript> scripts;
                if (!desc->Expand(i, provider, scripts, provider)) {
                    throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, strprintf("Cannot derive script without private keys: '%s'", desc_str));
                }
                needles.insert(scripts.begin(), scripts.end());
            }
        }

        // Scan the unspent transaction output set for inputs
        UniValue unspents(UniValue::VARR);
        std::vector<CTxOut> input_txos;
        std::map<COutPoint, Coin> coins;
        g_should_abort_scan = false;
        g_scan_progress = 0;
        int64_t count = 0;
        std::unique_ptr<CCoinsViewCursor> pcursor;
        {
            LOCK(cs_main);
            FlushStateToDisk();
            pcursor = std::unique_ptr<CCoinsViewCursor>(pcoinsdbview->Cursor());
            assert(pcursor);
        }
        bool res = FindScriptPubKey(g_scan_progress, g_should_abort_scan, count, pcursor.get(), needles, coins);
        result.pushKV("success", res);
        result.pushKV("searched_items", count);

        for (const auto& it : coins) {
            const COutPoint& outpoint = it.first;
            const Coin& coin = it.second;
            const CTxOut& txo = coin.out;
            input_txos.push_back(txo);
            total_in += txo.nValue;

            UniValue unspent(UniValue::VOBJ);
            unspent.pushKV("txid", outpoint.hash.GetHex());
            unspent.pushKV("vout", (int32_t)outpoint.n);
            unspent.pushKV("scriptPubKey", HexStr(txo.scriptPubKey));
            unspent.pushKV("amount", ValueFromAmount(txo.nValue));
            unspent.pushKV("height", (int32_t)coin.nHeight);

            unspents.push_back(unspent);
        }
        result.pushKV("unspents", unspents);
        result.pushKV("total_amount", ValueFromAmount(total_in));
    } else {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid command");
    }
    return result;
}



