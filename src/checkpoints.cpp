// Copyright (c) 2009-2019 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "txdb.h"
#include "main.h"
#include "uint256.h"


static const int nCheckpointSpan = 10;

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
        ( 0, hashGenesisBlock)
		( 1000,      uint256("0x328b55e5bcf00a6757269b325833d4dffd45476e915a0126088f0ecca206ba85") )
        ( 2000,      uint256("0x00000007d3081a12cc58d1484e1a04eb3496e4f38e48ee5e7a4ac23a1f7ccedc") )
        ( 5000,      uint256("0xddff08b5360c5ed917de623f4e017d4f88deebc615371ea459eb7b51b28ea96f") )
        ( 10000,      uint256("0xd96ddc18c9f43aa4cd5af7716a0ccc5c128ee19ceec2c86fa1a645bb3cf24135") )
        ( 15000,      uint256("0x07670e17c1bb21be00cff8a4e9f9dc4be498a907044f9410aea78ce6fbac6202") )
        ( 20000,      uint256("0x552080128009228f4b6756855303f3eb9864ce6deafbed8159665538ef316137") )
        ( 25000,      uint256("0xc527f61efe400a9c83149f198657c90c39a01650d03ecd94b8d7889f89932864") )
        ( 30000,      uint256("0x845b5c111c3212a882db040024ccc4e0f435a345d4de52946c62b3e58014e507") )
        ( 35000,      uint256("0x9214fa6d77ac483ad96abef3c6880a396bab525b91baa5e5636d71826d2e64a2") )
        ( 40000,      uint256("0xc67133d3fc1f81a8c3ad159b32ecfefac941106fcc929d03dbaa762c40677d84") )
        ( 45000,      uint256("0x4dc68c4bffc738394ed4b4696b289e877e09e7af903d8f6e5860095ba1fac254") )
        ( 50000,      uint256("0x5942d1227dd32b7275500f2458dde484d604472db030cf9fd94b31e97515ec92") )
        ( 55000,      uint256("0x4b0cb683152f737f8ec9cc8174fcc5fa3625a619dc84f92ec0788fba03480922") )
        ( 60000,      uint256("0xea4197fb0ee13a8876d097e6664db9cffe7bbc92a16daeb6f56fd46f13f134ec") )
        ( 65000,      uint256("0x98e39ef3f7c8190d7531f831d9f193e4bcfc99a85289e056cfc4ffa898fdf166") )
        ( 70000,      uint256("0xbed41554942e22fcd519ab51c2036fe1f4b80cb5ea7a251c1f6854b2ea570d38") )
        ( 75000,      uint256("0x0b4380700273aa8e4b663c850ba23aae6818ec3b42dc16612afccec1dd1cd8e2") )
        ( 80000,      uint256("0xbd40564ffaa54562336f3c70ecc605cd6cd6e570b4d8028961d381f46614fff9") )
        ( 85000,      uint256("0x8a3e44873a2ae2658e7ff58709d2948c1d6303db4be85eb72eabf6734aae3d6e") )
        ( 90000,      uint256("0xb06c46b7a02c30a627ccd3b4f18d510018f799c018233219682a7344741cd426") )
        ( 100000,      uint256("0x3f1daef67e2fcdd61736f60751661387dbf13b9b984c5a06dcb58b26711a7dc6") )
        ( 110000,      uint256("0x6504a314f38450fd0458687c358c15022fee49cb23b12f19c070b81578bc46ef") )
        ( 115000,      uint256("0x583eebb8759f99f962cad62cbe4a81554bb2a55afd3777e44d4a81eaf61fb995") )
        ( 120000,      uint256("0xbaae481fdbad020cf23fe27308dd721aa742a11cdff90760ce5599533d0db3cf") )
        ( 125000,      uint256("0x52b250712d728fe634532806f3571d73f5142b47bc8b52d67195390d6b40e50e") )
        ( 130000,      uint256("0x0ac91eb49213f72f4e7da131beb2ddfb51318fe2483be6461c9bee599c66ef6a") )
        ( 135000,      uint256("0x0c37eeb566b44a86e0554628b51cbb1d9a350a6a20fe5d56873b56bdb6b6497b") )
        ( 140000,      uint256("0x0cdceec90e5ed834290bf00fe366f128ace261066211d22bf3bd68673a78cc9d") )
        ( 145000,      uint256("0x0623ae05b37e4603f435386e97c65393622c05010daf486ae40905c0df728aeb") )
        ( 150000,      uint256("0x5b9fd17d49024d8530bdb7fcdba1a3b9dd8788c7f9028b6ea9ed63525570dfe5") )
        ( 155000,      uint256("0xad9ffec1ae8aab8cfd6891e2b8e311f03b2356a8d820cac8ba5d76bc07f27f1f") )
        ( 160000,      uint256("0x76019c312a1197f58d8de9c5f31752d5e70aaadeafd6947a7f3827c7198b5bae") )
        ( 165000,      uint256("0x25f1b1124a6a368367e9ba2b6f2b661e1bed5f92a0c6e30eca806ce301d1a3af") )
        ( 170000,      uint256("0x290139ef5ecb77008b6663860c25edd83aeb8aa5e480810f43fa158fbe1392aa") )
        ( 175000,      uint256("0x9a4c03c64ccfd2f2f5432249a4eb3ee567ad4816f80cc08de450abd861f8dc92") )
        ( 180000,      uint256("0xabefd5032b69f14690aeff4bc40a8af9116d898617ca9f67a08debadfdc6ca60") )
        ( 185000,      uint256("0x5254482166d2446e0e979352c7ee3fc94b2e0b776ef26469a6800c919f8a693e") )
        ( 190000,      uint256("0x33f37f5c5a91972b6e2e79c90ff55ed9ad033a96bf9e8c53b666a3a44d3b81e3") )
        ( 195000,      uint256("0x061fa5391b79248e03be18b8999758563ae9db1dd4c388f1411af08224d5735d") )
        ( 200000,      uint256("0x9a2f1ab6b0f2484ed7f6f21a7b7696a297928603a86db61613473223cfdb804c") )
        ( 250000,      uint256("0x9a696d3843849f6432a9e6765accc79762483f0fe42f0a2ff67cd308aa531496") )
        ( 300000,      uint256("0x1e0d77fd58296eb9491ff6d2fef30327b4ea561fca66ba9d960b793e28ade623") )
        ( 350000,      uint256("0xcf364bbd1a76705da0a1a34f80d01c0bf5a2a161f58b96095ba2e20132539973") )
        ( 400000,      uint256("0x9f45aae37d82d277eaa3d771c36eb0c250df088c6914198964848ade8fa9f563") )
        ( 450000,      uint256("0x6a80d0f384912611a46c46a4aa5d764fedf55d4753fefaa3376598e42a52c74e") )
        ( 500000,      uint256("0xda750931ac1ef1a22414f503220422e3f810d64fe154163279a8b382b1a0a3e4") )
        ( 550000,      uint256("0x65aeecfa355c56d62619c6964ad666fd4c7544726920f89676e1e451ce7c9f4a") )
        ( 600000,      uint256("0x781582cf5326e33b0ed13d3daf7febc1a50c233aa59911d26b8e1d264c9ed824") )
        ( 650000,      uint256("0xa713ad943ad3a99a66b73e9cccb2f4b1333a8465c66bc6c4d410c0713ae1e969") )
        ( 700000,      uint256("0x62fd8bcc55b22ecad6bf32f5701f61ea30d70cc6a02fcb216d3c5b7055de3845") )
        ( 750000,      uint256("0xbd82b2c259b6ce018d5a773c00da8e5f9f07275a042f94629ccd0925b4848bc4") )
        ( 800000,      uint256("0xf64954e6dae4e8b0ae7162f661cf0e01c407f25559b4039bd02841ee7589506f") )
        ( 830000,      uint256("0x71c427a21bbf83a4b6941748250a31ca5adcbf827d3b57d4ac68333280b4ed1f") )
		( 850000,	   uint256("0x97c32a1023e9a08c37707217d919c21b1c830fdfe3a8643b04ed3498cde2b3c6") )
		( 900000,      uint256("0xd9f7acba1c9b92477c1200d75eb90252b0fb2f6766432bbcce9dd4f15c441d26") )
		( 950000,      uint256("0x840e9c0d1226bddad5ae27c1ce83087562c7eea201c07fa2003c83fdc8312cdb") )
		( 1000000,     uint256("0x8c25cb39017e32fe6fe5a823f8c6df4bfbc58720b3b603227dc2b507601f6bac") )
		( 1050000,     uint256("0xd6f07a59fe9c82b6e9671341fe9a85f290d3e12a84a56c080c0238f9e8205d84") )
		( 1100000,     uint256("0x8ee8a05a150c92a9c84d77fd33e731a901849c9b0b38601f19962472f4beb6ad") )
		( 1150000,     uint256("0x129ab353d5309d75044cab52714f094bcb7061a272e488f313f8e82850b5cc21") )
		( 1200000,     uint256("0x50c0593c7dc56b61b0f9415da94495556d4a4d70d1e7e8957f80ed467c513b5b") )
		( 1205000,     uint256("0x4af5e5279792af501941816a9e49fddc465b84586bf1c865fda8e084b60c7903") )

    ;


    // TestNet has no checkpoints
    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        ( 0, hashGenesisBlockTestNet )
        ;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = (fTestNet ? mapCheckpointsTestnet : mapCheckpoints);

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, checkpoints)
        {
            const uint256& hash = i.second;
            std::map<uint256, CBlockIndex*>::const_iterator t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    // ppcoin: synchronized checkpoint (centrally broadcasted)
    uint256 hashSyncCheckpoint = 0;
    uint256 hashPendingCheckpoint = 0;
    CSyncCheckpoint checkpointMessage;
    CSyncCheckpoint checkpointMessagePending;
    uint256 hashInvalidCheckpoint = 0;
    CCriticalSection cs_hashSyncCheckpoint;

    // ppcoin: get last synchronized checkpoint
    CBlockIndex* GetLastSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        else
            return mapBlockIndex[hashSyncCheckpoint];
        return NULL;
    }

    // ppcoin: only descendant of current sync-checkpoint is allowed
    bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
    {
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        if (!mapBlockIndex.count(hashCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());

        CBlockIndex* pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        CBlockIndex* pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];

        if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
        {
            // Received an older checkpoint, trace back from current checkpoint
            // to the same height of the received checkpoint to verify
            // that current checkpoint should be a descendant block
            CBlockIndex* pindex = pindexSyncCheckpoint;
            while (pindex->nHeight > pindexCheckpointRecv->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("ValidateSyncCheckpoint: pprev null - block index structure failure");
            if (pindex->GetBlockHash() != hashCheckpoint)
            {
                hashInvalidCheckpoint = hashCheckpoint;
                return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
            }
            return false; // ignore older checkpoint
        }

        // Received checkpoint should be a descendant block of the current
        // checkpoint. Trace back to the same height of current checkpoint
        // to verify.
        CBlockIndex* pindex = pindexCheckpointRecv;
        while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");
        if (pindex->GetBlockHash() != hashSyncCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
        return true;
    }

    bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
    {
        CTxDB txdb;
        txdb.TxnBegin();
        if (!txdb.WriteSyncCheckpoint(hashCheckpoint))
        {
            txdb.TxnAbort();
            return error("WriteSyncCheckpoint(): failed to write to db sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
        if (!txdb.TxnCommit())
            return error("WriteSyncCheckpoint(): failed to commit to db sync checkpoint %s", hashCheckpoint.ToString().c_str());

        Checkpoints::hashSyncCheckpoint = hashCheckpoint;
        return true;
    }

    bool AcceptPendingSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint != 0 && mapBlockIndex.count(hashPendingCheckpoint))
        {
            if (!ValidateSyncCheckpoint(hashPendingCheckpoint))
            {
                hashPendingCheckpoint = 0;
                checkpointMessagePending.SetNull();
                return false;
            }

            CTxDB txdb;
            CBlockIndex* pindexCheckpoint = mapBlockIndex[hashPendingCheckpoint];
            if (!pindexCheckpoint->IsInMainChain())
            {
                CBlock block;
                if (!block.ReadFromDisk(pindexCheckpoint))
                    return error("AcceptPendingSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                if (!block.SetBestChain(txdb, pindexCheckpoint))
                {
                    hashInvalidCheckpoint = hashPendingCheckpoint;
                    return error("AcceptPendingSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
                }
            }

            if (!WriteSyncCheckpoint(hashPendingCheckpoint))
                return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
            hashPendingCheckpoint = 0;
            checkpointMessage = checkpointMessagePending;
            checkpointMessagePending.SetNull();
            printf("AcceptPendingSyncCheckpoint : sync-checkpoint at %s\n", hashSyncCheckpoint.ToString().c_str());
            // relay the checkpoint
            if (!checkpointMessage.IsNull())
            {
                BOOST_FOREACH(CNode* pnode, vNodes)
                    checkpointMessage.RelayTo(pnode);
            }
            return true;
        }
        return false;
    }

    // Automatically select a suitable sync-checkpoint 
    uint256 AutoSelectSyncCheckpoint()
    {
        const CBlockIndex *pindex = pindexBest;
        // Search backward for a block within max span and maturity window
        while (pindex->pprev && (pindex->GetBlockTime() + nCheckpointSpan * nTargetSpacing > pindexBest->GetBlockTime() || pindex->nHeight + nCheckpointSpan > pindexBest->nHeight))
            pindex = pindex->pprev;
        return pindex->GetBlockHash();
    }

    // Check against synchronized checkpoint
    bool CheckSync(const uint256& hashBlock, const CBlockIndex* pindexPrev)
    {
        if (fTestNet) return true; // Testnet has no checkpoints
        int nHeight = pindexPrev->nHeight + 1;

        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];

        if (nHeight > pindexSync->nHeight)
        {
            // trace back to same height as sync-checkpoint
            const CBlockIndex* pindex = pindexPrev;
            while (pindex->nHeight > pindexSync->nHeight)
                if (!(pindex = pindex->pprev))
                    return error("CheckSync: pprev null - block index structure failure");
            if (pindex->nHeight < pindexSync->nHeight || pindex->GetBlockHash() != hashSyncCheckpoint)
                return false; // only descendant of sync-checkpoint can pass check
        }
        if (nHeight == pindexSync->nHeight && hashBlock != hashSyncCheckpoint)
            return false; // same height with sync-checkpoint
        if (nHeight < pindexSync->nHeight && !mapBlockIndex.count(hashBlock))
            return false; // lower height than sync-checkpoint
        return true;
    }

    bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (hashPendingCheckpoint == 0)
            return false;
        if (hashBlock == hashPendingCheckpoint)
            return true;
        if (mapOrphanBlocks.count(hashPendingCheckpoint) 
            && hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
            return true;
        return false;
    }

    // ppcoin: reset synchronized checkpoint to last hardened checkpoint
    bool ResetSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        const uint256& hash = mapCheckpoints.rbegin()->second;
        if (mapBlockIndex.count(hash) && !mapBlockIndex[hash]->IsInMainChain())
        {
            // checkpoint block accepted but not yet in main chain
            printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
            CTxDB txdb;
            CBlock block;
            if (!block.ReadFromDisk(mapBlockIndex[hash]))
                return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
            if (!block.SetBestChain(txdb, mapBlockIndex[hash]))
            {
                return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
            }
        }
        else if(!mapBlockIndex.count(hash))
        {
            // checkpoint block not yet accepted
            hashPendingCheckpoint = hash;
            checkpointMessagePending.SetNull();
            printf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n", hashPendingCheckpoint.ToString().c_str());
        }

        BOOST_REVERSE_FOREACH(const MapCheckpoints::value_type& i, mapCheckpoints)
        {
            const uint256& hash = i.second;
            if (mapBlockIndex.count(hash) && mapBlockIndex[hash]->IsInMainChain())
            {
                if (!WriteSyncCheckpoint(hash))
                    return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
                printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
                return true;
            }
        }

        return false;
    }

    void AskForPendingSyncCheckpoint(CNode* pfrom)
    {
        LOCK(cs_hashSyncCheckpoint);
        if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocks.count(hashPendingCheckpoint)))
            pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
    }

    bool SetCheckpointPrivKey(std::string strPrivKey)
    {
        // Test signing a sync-checkpoint with genesis block
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = !fTestNet ? hashGenesisBlock : hashGenesisBlockTestNet;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        std::vector<unsigned char> vchPrivKey = ParseHex(strPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return false;

        // Test signing successful, proceed
        CSyncCheckpoint::strMasterPrivKey = strPrivKey;
        return true;
    }

    bool SendSyncCheckpoint(uint256 hashCheckpoint)
    {
        CSyncCheckpoint checkpoint;
        checkpoint.hashCheckpoint = hashCheckpoint;
        CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
        sMsg << (CUnsignedSyncCheckpoint)checkpoint;
        checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

        if (CSyncCheckpoint::strMasterPrivKey.empty())
            return error("SendSyncCheckpoint: Checkpoint master key unavailable.");
        std::vector<unsigned char> vchPrivKey = ParseHex(CSyncCheckpoint::strMasterPrivKey);
        CKey key;
        key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end())); // if key is not correct openssl may crash
        if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
            return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

        if(!checkpoint.ProcessSyncCheckpoint(NULL))
        {
            printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
            return false;
        }

        // Relay checkpoint
        {
            LOCK(cs_vNodes);
            BOOST_FOREACH(CNode* pnode, vNodes)
                checkpoint.RelayTo(pnode);
        }
        return true;
    }

    // Is the sync-checkpoint outside maturity window?
    bool IsMatureSyncCheckpoint()
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (nBestHeight >= pindexSync->nHeight + nCoinbaseMaturity ||
                pindexSync->GetBlockTime() + nStakeMinAge < GetAdjustedTime());
    }
}

// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "04a18357665ed7a802dcf252ef528d3dc786da38653b51d1ab8e9f4820b55aca807892a056781967315908ac205940ec9d6f2fd0a85941966971eac7e475a27826";

std::string CSyncCheckpoint::strMasterPrivKey = "";

// ppcoin: verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    CKey key;
    if (!key.SetPubKey(ParseHex(CSyncCheckpoint::strMasterPubKey)))
        return error("CSyncCheckpoint::CheckSignature() : SetPubKey failed");
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *(CUnsignedSyncCheckpoint*)this;
    return true;
}

// ppcoin: process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(Checkpoints::cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        Checkpoints::hashPendingCheckpoint = hashCheckpoint;
        Checkpoints::checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            pfrom->PushGetBlocks(pindexBest, hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)? WantedByOrphan(mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!Checkpoints::ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CTxDB txdb;
    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (!pindexCheckpoint->IsInMainChain())
    {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!block.ReadFromDisk(pindexCheckpoint))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        if (!block.SetBestChain(txdb, pindexCheckpoint))
        {
            Checkpoints::hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
