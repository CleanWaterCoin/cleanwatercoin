// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'
#include <boost/foreach.hpp>

#include "checkpoints.h"

#include "db.h"
#include "main.h"
#include "uint256.h"

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
        (      0, hashGenesisBlockOfficial )
        (   1000, uint256("0x0000001182cae66b8ce4615d022e2f36d43fb627fb2d77c19f3041eb2df6c427"))
        (   3500, uint256("0x0000000002c18dc3343dcd28b4106f000b375db7f8d269b982767cdbbffd73e9"))
        (   6000, uint256("0x000000000051ab10782806bd694f0993f4ab02b26f4cbd8462213cdf206f5287"))
        (   7500, uint256("0x0000000000e368852ca4d9902ec4400981ec0e856f7c9ece921c4b5bd7ba1f89"))
        (  10000, uint256("0x00000000228a6359e699fbdec637364c76c151bb1e0d8a6c9ba1e5b84f061d5c"))
        (  15439, uint256("0x00000006484f19549f317a599c028c06a10169186684429686db295f3d1b1531"))
        (  21044, uint256("0x000000030647967a11dba37030d470ed7ee9a7d7ac1617d3d939793c33b30753"))
        (  26443, uint256("0x0d42ea12901fb55769c1b51d4422a6f150ade4936614966377d983ac0e25174b"))
        (  29785, uint256("0x000000000da1c9ab8ff1dd2ab19ef08ff9c0190a3281f115d0de450bcaa991a8"))
        (  33947, uint256("0xf9e3101af45caf7e2463dee52f173967f37528d3a7ea74259934ebf40f877e54"))
        (  34399, uint256("0x000000002f0bb8fa5ad3eda6590c67b32ecb9f5c9e9642a04577f97a0bf8fb51"))
        (  37208, uint256("0x000000000ac6abcecc3113f0ccdf3af6028cd2666133bb979a70242144d280a2"))
        (  44186, uint256("0x354e60213449bcfe50d32494977652a9bd5241bc12c047285a7596003f867b9a"))
        (  48958, uint256("0x0000000021085a9aaa44681f6723de09f80e82b80d34b74f24496b92b8177eb1"))
        (  55699, uint256("0x000000003840bb3655fb974928a66d6bb9a490f62e8c3dab2078b8162ee624dc"))
        (  58143, uint256("0x02d0c96d0321c27949bdbc5ff15b10ce7195d29918cf68bd59d689468b360b45"))
        (  63368, uint256("0x298267dac655a9b711b8ce99d812a8b4edf7776fef66eeaeb172bc9476d4bf80"))
        (  66756, uint256("0xaaaa8b8e00c4758172c2ad4796b334d57a8ccb799433762718dd9efdc6ae76f1"))
        (  69838, uint256("0xeecfc66ec2cbe7f02bd5d1859bbb8621942298f92c5a91a5e36516ee893554a6"))
        (  70150, uint256("0x000000001dc06863b65815df6392f49bf82a4a72d1620acbeeb656bf1d94b9a1"))
        (  71095, uint256("0x135e6444e77a823d95e6c34a5f63a8a18896d6833ddf7094aa7b509b65ab7c8c"))
        (  71284, uint256("0xb032b6657ec41ffdb65c0d7c7701e853c4b7557fdaafa39896d4503c315a959c"))
        (  71573, uint256("0x3d31e3ead85b0d7a386bcb13a3e3240157fa3be906233e1cfa34539a06af3992"))
        (  72178, uint256("0xb8d6fbc56f067922b5ed2bebcd265d3af1f2a126868bf077e95735eab8ed3d70"))
        (  72385, uint256("0x50348e8caa9ff02b38ce2eedde3060ac2090a4705af69cb9b7450b84a602e908"))
        (  72400, uint256("0x459c56ce4d61427e6e8312ba5a72e5e09a63e5993d14b5dc5aea23e9d48e287b"))
        (  72486, uint256("0xb044c4f38e04f886d313b8e09c1e4b7e90321253a763cd25487c266a26892a96"))
        (  72682, uint256("0xf6eefb177eaaeeb85c655f5dd6a80b984e0b8748e5a9078eef672ec0b195840a"))
        (  73326, uint256("0x00000000660ba1e4f18edf779850a472f613c6cd0e8f2a03b5bec43542fb048e"))
        (  73339, uint256("0x00000000b21cdca4d5ec8447b29aaab5cd14c31c818f102df587e5ffe0408784"))
        (  73388, uint256("0x00000000598a0634ff588bb78cd65d8147b6807248bd3173579c2e2e4b9a41eb"))
        (  73630, uint256("0x7aeaa0c4bd7ca9b41ccb1c0abff3646961d81250a858b72965777a49d0a1373f"))
        (  73830, uint256("0x8510cf81f02c65a85338b52129fb4bd94b709b9c08fe809e1ec41720310de64f"))
        (  75204, uint256("0xb336b42ac216993f2cf2583fa6249fcfec7a2f384e2cf87a89053191095c357c"))
        (  75218, uint256("0xe41329bfcc980b1c15a2b04d94db5e45dd0ecab02aad89706731f01e3c752885"))
        (  75516, uint256("0x000000004a4032bf5e8e026fbef96124c46bfc795f03aed3e9a0b9f02c765392"))
        (  75606, uint256("0xcb96921e983f50a2e9d6d5805b1a84555375e5a59573c6011b6bce105192706d"))
        (  75759, uint256("0xa19018062897494d7cf9983b1bf5a1034c6d5d65c1ee1b3471f83e08152726b8"))
        (  75796, uint256("0x743043d1ceba719872dc442e277e5a2486f3cbe59ffb13f07b1f746f4c75c96d"))
        (  75926, uint256("0x5bc79406cc985c7d6373ec36fbb30aecce64fc1553ee9b4e099ef0b1c4d6d26a"))
        (  76056, uint256("0xfc6004f87f7df6a077c0d63658464c930e01069c503243db776a7e9ab31baab4"))
        (  76156, uint256("0xa70d2c07b4de182bf25a22e7bd3d805c64b671776cde5c1cd681e7a13dbf9e33"))
        (  76629, uint256("0x978a47b2306e4e4f46d69561c42e75a42bf014961edf1adf4b64b744ce01fc55"))
        (  77008, uint256("0x23ad4599cb0c052741734f00cdfccf907c75ab6fb3213dc945dbc8f120d5ed4a"))
        (  77101, uint256("0xbceea13221a390531c8f9967d0fba168759dc6d618d452f54d27c40b904e92fd"))
        (  77344, uint256("0x8e0bd51433dd02771151aec712b96b403f1971348c4b32fa0f80715574599616"))
        (  77364, uint256("0x56cc7188cf9d1130ef059f94235fe06d0cc55a3ac23b9ba6527e0b3c03fef766"))
        (  77515, uint256("0x3f4b02b88a4d455df37ec46c1f9831b3200d7e3153604f1368eb2a0596999bf0"))
        (  77611, uint256("0xfc6234334cbe1a24326df25126c2e45f38780f3daa1b464629fca4215c57b37d"))
        (  77653, uint256("0x3d8b02947d11ce933f1cb811aa204c820737a0aff09d9e1cb3c58e8fbf9146a4"))
        (  77695, uint256("0x6fa0294d0a7a8ef13ef06308a70cfe559bfb251a585d0e54788403256b45f22f"))
        (  77847, uint256("0xe45d6c4bab8233f8e5de33626aa46be6dcd098878c7a6a9f520056ccb5deae0d"))
        (  77948, uint256("0x453d5d855e8fa438af680a5f1ff63e67c6456b70d6a1297b1d1699394bd1e01f"))
        (  78771, uint256("0xd21eba6dabfbbf0afb764de5c7eb4bd1fe4fa06d550f9329edab279374a6d567"))
        (  79816, uint256("0xdbf8d46c1eeb40cd8f060e17f196643afde928d221d56363b7e193b1faf70fee"))
        (  79817, uint256("0xf400ba153937e49e1c997b5d0f1fd59291b4999874c0284899a8d7a60e11513b"))
        (  79818, uint256("0x6b072349c2bbba75c2253a9627ce545241aa2e465dacef49bc5342c517ac41fe"))
        (  79822, uint256("0xa48f5c9f004b436c26b9d410eb4780381763ef457cec6d13ffbfda2a1a6941ae"))
        (  79828, uint256("0x1610b96c98422a0edcd03c8aa262ba312a08f7e31b512c1c97ab046585f65532"))
        (  80163, uint256("0x3f3ca39457b189ce83e41383bec9b0756fa230f3be353e2619924fefafaa4252"))
        (  80260, uint256("0x1f5776b3f7c810dc7265d59d152fdb78930b4c002a90d0d030c4bd5e1b0b6aa0"))
        (  80476, uint256("0x0422c76771255d1aff3adfc9176075b8fa9e02d5939b739fb205523ea56d0c7a"))
        (  80703, uint256("0xd85ed7ff5b25530731755f550dfbc7e21327837c9884b9ad734ddacdfcdd8d5e"))
        (  80756, uint256("0x73c3e6def8ef184c75655fff5381ce7e6bd5beb9f0aa8839625d438467fcccf8"))
        (  80757, uint256("0xefbc91b3939502c0da729d36e18cf3a5ea7b69972185d669dbb1292463de309e"))
        (  80810, uint256("0xd2a6391e287cb7f928cdef1d4cc960f2d89d99a5825e10d59ecc1ab561e4d194"))
        (  80819, uint256("0x673e390ec40f2ae5ba3feeedd350a20e8a08349d1732a9e3b1b61ee6ccbee3bd"))
        (  80826, uint256("0x922966f585c39aa37fb6ccd89e95cdd805b90fc65c8f0ff12e67f86ec50a4d20"))
        (  80907, uint256("0x3904a8b7b564e741e29e5b66faa17981238a9a77419d16c8d61536b5eb4fdab3"))
        (  80912, uint256("0xc32f92a721385c6ef469fc8d47a1c4d1fc74c2f2887ca0c7740e877ddb35c0fb"))
        (  82023, uint256("0x00000000469cdd132c65e4602b02639eeb9e49328264a2655237e4ebab4092dd"))
        (  82161, uint256("0x000000001ea7a5b196ddf8092ccd0d046895f1e1b077508d2533a49221f7ad10"))
        (  82167, uint256("0xf6e233344442038e6f0d4ceefe5c2ab10d86757ae1e83fef29654757237f34cb"))
        (  82214, uint256("0x000000001949779f6890d72ebdb404bfb120dd7804f5a8a263de08ef02a09e26"))
        (  83102, uint256("0x00000000478677539d30b06c9b8d6357443c77125a62bc11f88464fdbdd99165"))
        (  83103, uint256("0xd2ac28e3832f8a91ff202197a9292e821d08368ece0970aa4b9959305c4bf0f5"))
        (  83564, uint256("0xdae00515c97325dcd0ed57ffdb6ad0da41b7599fe3955d7aedff4b608118ceff"))
        (  84876, uint256("0x000000021589bbc8a2d837977cbbd275d42eab02ec8d2cdebd372c67d24271a1"))
        (  85200, uint256("0x00000000bf64bd6d8d6317ccbc3e25bb53d90e249732dd189b5677f2d7b9d533"))
        (  87530, uint256("0x0000000071b885f00d7a74002cdf56ec4cefcc4edb84d8b7fc93a9d509d294ca"))
        (  88172, uint256("0x218f00845e999889368f325c39e8fec145fa673573bcce80281ed51e5ed0532d"))
        (  89280, uint256("0x22b2142502ca9468f69b31580671ee2130a2af0faaba4f26910257e55c2da9ed"))
        (  89551, uint256("0x09ad0b5215059270903c32caf25e87ce18352ffa4557de4ed4c3124004d47609"))
        (  89573, uint256("0x809c9fca6f353204f8c7890c05e0817670f8259c1bf0edc837dee204123ec964"))
        (  89963, uint256("0x7869c60a1689025d47fc288bfa0a245a62e32480d0ca785783f7162efd6fd168"))
        (  91540, uint256("0x00000000331dedf927f1de3bed1a0673027784ce94e684f3461f042673caccaf"))
        (  91696, uint256("0x5bc10507815519755799875f97ac98fedb36d124fe5da3fa084db60ef7591689"))
        (  92309, uint256("0xa8e4e9e19379cd6b3f4e8d4f3ec2f4c00a95b169cc4b4c892f8e9959b4ac8480"))
        (  92533, uint256("0x0cff5b2d76e94ab13e5a29cba0f55ae9344de905570945dd5fed8c5b8167fd24"))
        (  92921, uint256("0x72d51e5e3739d6b016258373c2b364f473ef0c66575fa78016e03cec0c5cd63d"))
        (  94888, uint256("0x000000004b52c5c10f064eb95ddf496251a62f89c0451a380dfa9f6aa93e256b"))
        (  95063, uint256("0x00c98a50f62d7e7334466d7260e237e69ea955af2896a45d8b9bde365b4bc25b"))
        (  95431, uint256("0x020ba82ea8a3aac25e3725c70b72568edcd0633f0be2931849c158bcd534e312"))
        (  95938, uint256("0xddac9a040a54266e5cd70d0841ec7202a52e6d40c059277c0b7cad08aad15f54"))
        (  95958, uint256("0x6bdaaef87f1c4b9e17cbdab0c3b35a769e016c9cb84131d3ad992f51791d847f"))
        (  97872, uint256("0x00000000c180081e2e4379b4d780700b3602ffefee75f2dfc29cff253621fb99"))
        (  97883, uint256("0xce852e5e1b5852a6a6c363786f7a6416dc59774350813d5e9581346036840286"))
        (  97902, uint256("0x548e055e34edf4a8f7d7fba834a227859091710bdc7c912221c6ae45676e5ac7"))
        (  98075, uint256("0x1ab3a64126fd0308723c727c236c21b9ba5222771f29fd8bf4feafa403269510"))
        (  98309, uint256("0x000000004c52da7c4b9b0115cc6477af2522d208d493af0fdfa582edbddb30cf"))
        (  99472, uint256("0xa9d74cdf05d17dc72b0b3a4da50269b32f2d8b46f5e2253469502e671dd2dc75"))
        (  99739, uint256("0x000000007b19a84cd5390a498a426fab14647c3566ef2751d0e9dfb5038c8006"))
        ( 100354, uint256("0x31fa0b198c014c28183c32c50dfbdf1da882667a5e8bb1ed55faaccbd19866a4"))
        ( 100509, uint256("0x209036c96efdc91cabae51f2105ba430dd9a32c15647aee1ca08b868a32a318f"))
        ( 100564, uint256("0xf10c320d0914aebb82c04068e0543276a4296a57b88b326514e5a859e212fbc7"))
        ( 100751, uint256("0x2a555cf948b3f5883e953dfc85498416140a879f43d4e0fd304ed2e36bc3c378"))
        ( 100801, uint256("0xba69a8a172be414e280a6f529c554cd9822d5e47b2e46b22de15b5dc9f8903d4"))
        ( 100829, uint256("0x576db3732d99cbf9f94bfa02c42c61863ec26d87245c9f97b6d354d91fac6323"))
        ( 100939, uint256("0xed41638273586af1d3a598c0d03e64c58063af268d7a9c5e50060bcffee5c117"))
        ( 100977, uint256("0x248d5bc652acb52c2fdc3ca21b1408721c43c09309389d8b27cb5e77b732073b"))
        ( 101354, uint256("0x2f6ded6af7ffef8a124978d5934d6e0bafe6f9bb0a79b0356ba55f09407092a5"))
        ( 101501, uint256("0x03ac5656731a20be457ee2723aee805e67f18962183afeb524328f1b29d2d394"))
        ( 101511, uint256("0xdc9e661fbaa1d66604b38d4e912bac78a8d38ecfecf4077cbb06b2126765579c"))
        ( 101990, uint256("0x11f8519bd410f40eac9c36a9f108fc6cee232da4e3bd6fb9724428d2cc220eaa"))
        ( 102066, uint256("0xcb8fe76fe2c8437210a1c247c24cdf2f714680632910cc022e611adde341db82"))
        ( 102156, uint256("0x36bb23ded5186ddfa9c1539b57ab85068e8437a62cd7acd91118c86ae7caf4d5"))
        ( 102442, uint256("0x72b9d8e6395f3cb12fea441dd90a5653c7a6a089eb29e3f65ab632470b4033c5"))
        ( 102515, uint256("0x0ef21274aa557c136badfe57aee5d097732f9de52be8944dfe881583687ce040"))
        ( 102584, uint256("0x7f0075103d6a29c0151c78e2c7efb89f4bcf28cca147fbb3b0b0931801e065d4"))
        ( 102716, uint256("0x93efddb5d079ddf03032d361e40948ae4a424914be742b643c362703e65fdf3b"))
        ( 102811, uint256("0x15de227d28b09dddb95b316da7257126a16acadeb1ebf53be6bfe1acfc1998de"))
        ( 102992, uint256("0x263199bb0a82c31c2bdb15cd192fdfcd2dff548d30ac4dc419409083803bdc95"))
        ( 103059, uint256("0x00000000317914a9a8be9d74f3d9a33e5813b9ffb5cfd8a66453bd82ae88c72b"))
        ( 103357, uint256("0x5403efd69b3a6f07edf2171ca030f5a6ce10506de3a5c558e30808aedeb32828"))
        ( 103423, uint256("0x882f32d6050534e0129946f63a514eb5d515654c4949378308e1e43a82768e0a"))
        ( 103619, uint256("0xa81c60d0962e8ee6b873970d2b67f807fc1bccb3afb9ef8e9c5aef7eddcb7b52"))
        ( 103961, uint256("0xd6800bbbade51380871f67f15549043e3ba4cd2b926cef33cef42da5acad0fb8"))
        ( 104240, uint256("0x91cff88964a691128dcba9079a51a71556ee4744b19abe05dab9794af8bb766a"))
        ( 104241, uint256("0x00000000318af1150c04621aba515cf3115f88ecd6eaf715a8a0010f12770bfe"))
        ( 104559, uint256("0xa3782bfe22fbc00086b635fd45e111debb80141c03a14ef5549fbdc5390047f7"))
        ( 104662, uint256("0x95f9824e3c36392cbf7b317debbe6d240d3dbcdb33f513dd570c114c01dc65d4"))
        ( 105525, uint256("0xbf77c0fbb36df278a2d25bc8b8e2394eb38f2645bd06de07ca71b73b6fe7ebfa"))
        ( 105182, uint256("0x8a73c3bc598c7178ac2f2ed9d4ba3a288486e13a6880e7fd3d5e48296338c372"))
        ( 105406, uint256("0x4679cd8908eedab669f3d1eb30f7a6ad304502090b3ce7a1d7ea4479146896bc"))
        ( 105417, uint256("0xb0fd7dccf5754f8d65993d11e9a8b577c2185c8662827818a6d985d5d9bc962f"))
        ( 105973, uint256("0x90bb2e4a30aaaeeccb7680b79e4595151039fc92c0106c4de518d48c0d45d24a"))
        ( 106443, uint256("0x000000014984b84c06687543aa8f49c6f2467008470419a82fe263590ca8a4f2"))
        ( 107447, uint256("0x000000003ae60723a6b37a0510954606d871c6691c891455a58c28ac0bd91003"))
        ( 107751, uint256("0x9f983240e47003a4ca59e6f83835e22ce20abe8a29bfd297cf35d37b62abd3b7"))
        ( 107998, uint256("0x4cfc6a10c1e0def5602c450598a789e8bf4c00bae2231b25f508b685711a0764"))
        ( 108228, uint256("0x24272832ad0e39bbdf10ddc3460679d0047a53d28077e38650026cd6e6ed21e5"))
        ( 108671, uint256("0xcbb782188fda3e954a6e88400cce33dea926ea11ba4866d3e77b4993e0430b9f"))
        ( 108915, uint256("0xbaf85d98e40de8f7a0c9b89fbdc42305213558715bfdc9236c3ac15d86107248"))
        ( 109190, uint256("0x8394ae6bfbcf016ec403fad5c799105d17cb5769aefdda323f51b78e5a3936cc"))
        ( 109442, uint256("0x88395503cedf0d22d94ee3b339682f48383929de11a2722d68101b792ac3bd5e"))
        ( 109561, uint256("0x58dfa36b58fedde07db36ec3d53ba085ff17043afb0cd894212ac0818938c699"))
        ( 109706, uint256("0xf31c3e1a7f6ca6af630e15bca0f0f74a2ee9f60ba92da4da120a18fd2a8bfc3b"))
        ( 109739, uint256("0x000000003370cbb513af63612d624e0c655b495d7a64f201d2352f34e0315e51"))
        ;


    static MapCheckpoints mapCheckpointsTestnet =
        boost::assign::map_list_of
        (     0, hashGenesisBlockOfficial )
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
                    return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
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
        txdb.Close();

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
            txdb.Close();

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
        // Proof-of-work blocks are immediately checkpointed
        // to defend against 51% attack which rejects other miners block 

        // Select the last proof-of-work block
        const CBlockIndex *pindex = GetLastBlockIndex(pindexBest, false);
        // Search forward for a block within max span and maturity window
        while (pindex->pnext && (pindex->GetBlockTime() + CHECKPOINT_MAX_SPAN <= pindexBest->GetBlockTime() || pindex->nHeight + std::min(6, nCoinbaseMaturity - 20) <= pindexBest->nHeight))
            pindex = pindex->pnext;
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
            txdb.Close();
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

    // Is the sync-checkpoint too old?
    bool IsSyncCheckpointTooOld(unsigned int nSeconds)
    {
        LOCK(cs_hashSyncCheckpoint);
        // sync-checkpoint should always be accepted block
        assert(mapBlockIndex.count(hashSyncCheckpoint));
        const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
        return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
    }
}

// ppcoin: sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "041b69292996c25baeb7ffa399b31edfebcebc0173c5ea01522f8e2fe822466cb5f1420d15356f9dda421a6dfd82a379a02dd529cee3774514b101ca3b11ed2e55";

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
    txdb.Close();

    if (!Checkpoints::WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    Checkpoints::checkpointMessage = *this;
    Checkpoints::hashPendingCheckpoint = 0;
    Checkpoints::checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
