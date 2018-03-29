// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXMEMPOOL_H
#define BITCOIN_TXMEMPOOL_H

#include <memory>
#include <set>
#include <map>
#include <vector>
#include <utility>
#include <string>

#include <amount.h>
#include <coins.h>
#include <indirectmap.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <sync.h>
#include <random.h>

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/signals2/signal.hpp>

class CBlockIndex;

/** Fake height value used in Coin to signify they are only in the memory pool (since 0.8) */
static const uint32_t MEMPOOL_HEIGHT = 0x7FFFFFFF;

struct LockPoints
{
    // Will be set to the blockchain height and median time past
    // values that would be necessary to satisfy all relative locktime
    // constraints (BIP68) of this tx given our view of block chain history
    int height;
    int64_t time;
    // As long as the current chain descends from the highest height block
    // containing one of the inputs used in the calculation, then the cached
    // values are still valid even after a reorg.
    CBlockIndex* maxInputBlock;

    LockPoints() : height(0), time(0), maxInputBlock(nullptr) { }
};

class CTxMemPool;

/** \class CTxMemPoolEntry
 *
 * CTxMemPoolEntry stores data about the corresponding transaction, as well
 * as data about all in-mempool transactions that depend on the transaction
 * ("descendant" transactions).
 *
 * When a new entry is added to the mempool, we update the descendant state
 * (nCountWithDescendants, nSizeWithDescendants, and nModFeesWithDescendants) for
 * all ancestors of the newly added transaction.
 * CtxMemPoolEntry 存储交易和该交易的所有子孙交易.
 * 当一个新的 entry 添加到 mempool 中时，我们更新它的所有子孙状态和祖先状态
 */

class CTxMemPoolEntry
{
private:
    CTransactionRef tx;	// 交易引用
    CAmount nFee;              //!< Cached to avoid expensive parent-transaction lookups 交易费用
    size_t nTxWeight;          //!< ... and avoid recomputing tx weight (also used for GetTxSize())
    size_t nUsageSize;         //!< ... and total memory usage 大小
    int64_t nTime;             //!< Local time when entering the mempool 时间戳
    unsigned int entryHeight;  //!< Chain height when entering the mempool 区块高度
    bool spendsCoinbase;       //!< keep track of transactions that spend a coinbase 前一个交易是否是 coinbase
    int64_t sigOpCost;         //!< Total sigop cost
    int64_t feeDelta;          //!< Used for determining the priority of the transaction for mining in a block 调整交易的优先级
    LockPoints lockPoints;     //!< Track the height and time at which tx was final 交易最后的所在区块高度和打包的时间

    // Information about descendants of this transaction that are in the
    // mempool; if we remove this transaction we must remove all of these
    // descendants as well.
    /**
     * 子孙交易信息，如果我们移除一个交易，必须同时移除它的所有子孙交易
     */
    uint64_t nCountWithDescendants;  //!< number of descendant transactions 子孙交易的数量
    uint64_t nSizeWithDescendants;   //!< ... and size 大小
    CAmount nModFeesWithDescendants; //!< ... and total fees (all including us) 费用和, 包括当前交易

    // Analogous statistics for ancestor transactions
    // 祖先交易信息
    uint64_t nCountWithAncestors;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    int64_t nSigOpCostWithAncestors;

public:
    CTxMemPoolEntry(const CTransactionRef& _tx, const CAmount& _nFee,
                    int64_t _nTime, unsigned int _entryHeight,
                    bool spendsCoinbase,
                    int64_t nSigOpsCost, LockPoints lp);

    const CTransaction& GetTx() const { return *this->tx; }
    CTransactionRef GetSharedTx() const { return this->tx; }
    const CAmount& GetFee() const { return nFee; }
    size_t GetTxSize() const;
    size_t GetTxWeight() const { return nTxWeight; }
    int64_t GetTime() const { return nTime; }
    unsigned int GetHeight() const { return entryHeight; }
    int64_t GetSigOpCost() const { return sigOpCost; }
    int64_t GetModifiedFee() const { return nFee + feeDelta; }
    size_t DynamicMemoryUsage() const { return nUsageSize; }
    const LockPoints& GetLockPoints() const { return lockPoints; }

    // Adjusts the descendant state.
    // 更新子孙状态
    void UpdateDescendantState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount);

    // Adjusts the ancestor state
    // 更新祖先状态
    void UpdateAncestorState(int64_t modifySize, CAmount modifyFee, int64_t modifyCount, int64_t modifySigOps);

    // Updates the fee delta used for mining priority score, and the
    // modified fees with descendants.
    // 更新feeDelta，并且修改子孙交易费用
    void UpdateFeeDelta(int64_t feeDelta);

    // Update the LockPoints after a reorg
    // 更新LockPoint
    void UpdateLockPoints(const LockPoints& lp);

    uint64_t GetCountWithDescendants() const { return nCountWithDescendants; }
    uint64_t GetSizeWithDescendants() const { return nSizeWithDescendants; }
    CAmount GetModFeesWithDescendants() const { return nModFeesWithDescendants; }

    bool GetSpendsCoinbase() const { return spendsCoinbase; }

    uint64_t GetCountWithAncestors() const { return nCountWithAncestors; }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    int64_t GetSigOpCostWithAncestors() const { return nSigOpCostWithAncestors; }

    mutable size_t vTxHashesIdx; //!< Index in mempool's vTxHashes
};

// Helpers for modifying CTxMemPool::mapTx, which is a boost multi_index.
struct update_descendant_state
{
    update_descendant_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount) :
        modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount)
    {}

    void operator() (CTxMemPoolEntry &e)
        { e.UpdateDescendantState(modifySize, modifyFee, modifyCount); }

    private:
        int64_t modifySize;
        CAmount modifyFee;
        int64_t modifyCount;
};

struct update_ancestor_state
{
    update_ancestor_state(int64_t _modifySize, CAmount _modifyFee, int64_t _modifyCount, int64_t _modifySigOpsCost) :
        modifySize(_modifySize), modifyFee(_modifyFee), modifyCount(_modifyCount), modifySigOpsCost(_modifySigOpsCost)
    {}

    void operator() (CTxMemPoolEntry &e)
        { e.UpdateAncestorState(modifySize, modifyFee, modifyCount, modifySigOpsCost); }

    private:
        int64_t modifySize;
        CAmount modifyFee;
        int64_t modifyCount;
        int64_t modifySigOpsCost;
};

struct update_fee_delta
{
    explicit update_fee_delta(int64_t _feeDelta) : feeDelta(_feeDelta) { }

    void operator() (CTxMemPoolEntry &e) { e.UpdateFeeDelta(feeDelta); }

private:
    int64_t feeDelta;
};

struct update_lock_points
{
    explicit update_lock_points(const LockPoints& _lp) : lp(_lp) { }

    void operator() (CTxMemPoolEntry &e) { e.UpdateLockPoints(lp); }

private:
    const LockPoints& lp;
};

// extracts a transaction hash from CTxMempoolEntry or CTransactionRef
struct mempoolentry_txid
{
    typedef uint256 result_type;
    result_type operator() (const CTxMemPoolEntry &entry) const
    {
        return entry.GetTx().GetHash();
    }

    result_type operator() (const CTransactionRef& tx) const
    {
        return tx->GetHash();
    }
};

/** \class CompareTxMemPoolEntryByDescendantScore
 *
 *  Sort an entry by max(score/size of entry's tx, score/size with all descendants).
 */
class CompareTxMemPoolEntryByDescendantScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        double a_mod_fee, a_size, b_mod_fee, b_size;

        GetModFeeAndSize(a, a_mod_fee, a_size);
        GetModFeeAndSize(b, b_mod_fee, b_size);

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = a_mod_fee * b_size;
        double f2 = a_size * b_mod_fee;

        if (f1 == f2) {
            return a.GetTime() >= b.GetTime();
        }
        return f1 < f2;
    }

    // Return the fee/size we're using for sorting this entry.
    void GetModFeeAndSize(const CTxMemPoolEntry &a, double &mod_fee, double &size) const
    {
        // Compare feerate with descendants to feerate of the transaction, and
        // return the fee/size for the max.
        double f1 = (double)a.GetModifiedFee() * a.GetSizeWithDescendants();
        double f2 = (double)a.GetModFeesWithDescendants() * a.GetTxSize();

        if (f2 > f1) {
            mod_fee = a.GetModFeesWithDescendants();
            size = a.GetSizeWithDescendants();
        } else {
            mod_fee = a.GetModifiedFee();
            size = a.GetTxSize();
        }
    }
};

/** \class CompareTxMemPoolEntryByScore
 *
 *  Sort by feerate of entry (fee/size) in descending order
 *  This is only used for transaction relay, so we use GetFee()
 *  instead of GetModifiedFee() to avoid leaking prioritization
 *  information via the sort order.
 */
class CompareTxMemPoolEntryByScore
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        double f1 = (double)a.GetFee() * b.GetTxSize();
        double f2 = (double)b.GetFee() * a.GetTxSize();
        if (f1 == f2) {
            return b.GetTx().GetHash() < a.GetTx().GetHash();
        }
        return f1 > f2;
    }
};

class CompareTxMemPoolEntryByEntryTime
{
public:
    bool operator()(const CTxMemPoolEntry& a, const CTxMemPoolEntry& b) const
    {
        return a.GetTime() < b.GetTime();
    }
};

/** \class CompareTxMemPoolEntryByAncestorScore
 *
 *  Sort an entry by min(score/size of entry's tx, score/size with all ancestors).
 */
class CompareTxMemPoolEntryByAncestorFee
{
public:
    template<typename T>
    bool operator()(const T& a, const T& b) const
    {
        double a_mod_fee, a_size, b_mod_fee, b_size;

        GetModFeeAndSize(a, a_mod_fee, a_size);
        GetModFeeAndSize(b, b_mod_fee, b_size);

        // Avoid division by rewriting (a/b > c/d) as (a*d > c*b).
        double f1 = a_mod_fee * b_size;
        double f2 = a_size * b_mod_fee;

        if (f1 == f2) {
            return a.GetTx().GetHash() < b.GetTx().GetHash();
        }
        return f1 > f2;
    }

    // Return the fee/size we're using for sorting this entry.
    template <typename T>
    void GetModFeeAndSize(const T &a, double &mod_fee, double &size) const
    {
        // Compare feerate with ancestors to feerate of the transaction, and
        // return the fee/size for the min.
        double f1 = (double)a.GetModifiedFee() * a.GetSizeWithAncestors();
        double f2 = (double)a.GetModFeesWithAncestors() * a.GetTxSize();

        if (f1 > f2) {
            mod_fee = a.GetModFeesWithAncestors();
            size = a.GetSizeWithAncestors();
        } else {
            mod_fee = a.GetModifiedFee();
            size = a.GetTxSize();
        }
    }
};

// Multi_index tag names
struct descendant_score {};
struct entry_time {};
struct ancestor_score {};

class CBlockPolicyEstimator;

/**
 * Information about a mempool transaction.
 */
struct TxMempoolInfo
{
    /** The transaction itself */
    CTransactionRef tx;

    /** Time the transaction entered the mempool. */
    int64_t nTime;

    /** Feerate of the transaction. */
    CFeeRate feeRate;

    /** The fee delta. */
    int64_t nFeeDelta;
};

/** Reason why a transaction was removed from the mempool,
 * this is passed to the notification signal.
 */
enum class MemPoolRemovalReason {
    UNKNOWN = 0, //! Manually removed or unknown reason
    EXPIRY,      //! Expired from mempool
    SIZELIMIT,   //! Removed in size limiting
    REORG,       //! Removed for reorganization
    BLOCK,       //! Removed for block
    CONFLICT,    //! Removed for conflict with in-block transaction
    REPLACED     //! Removed for replacement
};

class SaltedTxidHasher
{
private:
    /** Salt */
    const uint64_t k0, k1;

public:
    SaltedTxidHasher();

    size_t operator()(const uint256& txid) const {
        return SipHashUint256(k0, k1, txid);
    }
};

/**
 * CTxMemPool stores valid-according-to-the-current-best-chain transactions
 * that may be included in the next block.
 *
 * Transactions are added when they are seen on the network (or created by the
 * local node), but not all transactions seen are added to the pool. For
 * example, the following new transactions will not be added to the mempool:
 * - a transaction which doesn't meet the minimum fee requirements.
 * - a new transaction that double-spends an input of a transaction already in
 * the pool where the new transaction does not meet the Replace-By-Fee
 * requirements as defined in BIP 125.
 * - a non-standard transaction.
 *
 * CTxMemPool::mapTx, and CTxMemPoolEntry bookkeeping:
 *
 * mapTx is a boost::multi_index that sorts the mempool on 4 criteria:
 * - transaction hash
 * - descendant feerate [we use max(feerate of tx, feerate of tx with all descendants)]
 * - time in mempool
 * - ancestor feerate [we use min(feerate of tx, feerate of tx with all unconfirmed ancestors)]
 *
 * Note: the term "descendant" refers to in-mempool transactions that depend on
 * this one, while "ancestor" refers to in-mempool transactions that a given
 * transaction depends on.
 *
 * In order for the feerate sort to remain correct, we must update transactions
 * in the mempool when new descendants arrive.  To facilitate this, we track
 * the set of in-mempool direct parents and direct children in mapLinks.  Within
 * each CTxMemPoolEntry, we track the size and fees of all descendants.
 *
 * Usually when a new transaction is added to the mempool, it has no in-mempool
 * children (because any such children would be an orphan).  So in
 * addUnchecked(), we:
 * - update a new entry's setMemPoolParents to include all in-mempool parents
 * - update the new entry's direct parents to include the new tx as a child
 * - update all ancestors of the transaction to include the new tx's size/fee
 *
 * When a transaction is removed from the mempool, we must:
 * - update all in-mempool parents to not track the tx in setMemPoolChildren
 * - update all ancestors to not include the tx's size/fees in descendant state
 * - update all in-mempool children to not include it as a parent
 *
 * These happen in UpdateForRemoveFromMempool().  (Note that when removing a
 * transaction along with its descendants, we must calculate that set of
 * transactions to be removed before doing the removal, or else the mempool can
 * be in an inconsistent state where it's impossible to walk the ancestors of
 * a transaction.)
 *
 * In the event of a reorg, the assumption that a newly added tx has no
 * in-mempool children is false.  In particular, the mempool is in an
 * inconsistent state while new transactions are being added, because there may
 * be descendant transactions of a tx coming from a disconnected block that are
 * unreachable from just looking at transactions in the mempool (the linking
 * transactions may also be in the disconnected block, waiting to be added).
 * Because of this, there's not much benefit in trying to search for in-mempool
 * children in addUnchecked().  Instead, in the special case of transactions
 * being added from a disconnected block, we require the caller to clean up the
 * state, to account for in-mempool, out-of-block descendants for all the
 * in-block transactions by calling UpdateTransactionsFromBlock().  Note that
 * until this is called, the mempool state is not consistent, and in particular
 * mapLinks may not be correct (and therefore functions like
 * CalculateMemPoolAncestors() and CalculateDescendants() that rely
 * on them to walk the mempool are not generally safe to use).
 *
 * Computational limits:
 *
 * Updating all in-mempool ancestors of a newly added transaction can be slow,
 * if no bound exists on how many in-mempool ancestors there may be.
 * CalculateMemPoolAncestors() takes configurable limits that are designed to
 * prevent these calculations from being too CPU intensive.
 *
 * 交易内存池，保存所有在当前主链上有效的交易.
 * 当交易在网络上广播之后，就会被加进交易池.
 * 但并不是所有的交易都会被加入
 * 例如交易费太小的或者　双花的交易或者非标准交易
 * 内存池中通过一个 boost::multi_index 类型的变量　mapTx 来排序所有交易
 * 按照下面四个标准:
 * - 交易hash
 * - 交易费(包括所有子孙交易)
 * - 在mempool中的时间
 * - 挖矿分数
 *
 * 为了保证交易费的正确性，当新交易被加进 mempool 时，我们必须更新该交易的所有祖先交易信息，而这个操作可能会导致处理速度变慢，
 * 所以必须对更新祖先的数量进行限制.
 */
class CTxMemPool
{
private:
    uint32_t nCheckFrequency; //!< Value n means that n times in 2^32 we check. 表示在 2^32 时间内检查的次数
    unsigned int nTransactionsUpdated; //!< Used by getblocktemplate to trigger CreateNewBlock() invocation
    CBlockPolicyEstimator* minerPolicyEstimator;

    // 所有 mempool 中交易的虚拟大小，不包括见证数据
    uint64_t totalTxSize;      //!< sum of all mempool tx's virtual sizes. Differs from serialized tx size since witness data is discounted. Defined in BIP 141.

    // map 中元素使用的动态内存大小之和
    uint64_t cachedInnerUsage; //!< sum of dynamic memory usage of all the map elements (NOT the maps themselves)

    mutable int64_t lastRollingFeeUpdate;
    mutable bool blockSinceLastRollingFeeBump;

    // 进入 pool 需要的最小费用
    mutable double rollingMinimumFeeRate; //!< minimum fee to get into the pool, decreases exponentially

    void trackPackageRemoved(const CFeeRate& rate);

public:

    static const int ROLLING_FEE_HALFLIFE = 60 * 60 * 12; // public only for testing

    typedef boost::multi_index_container<
        CTxMemPoolEntry,
        boost::multi_index::indexed_by<
            // sorted by txid 首先根据交易的 hash 排
            boost::multi_index::hashed_unique<mempoolentry_txid, SaltedTxidHasher>,
            // sorted by fee rate 然后是费用
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<descendant_score>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByDescendantScore
            >,
            // sorted by entry time 然后是时间
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<entry_time>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByEntryTime
            >,
            // sorted by fee rate with ancestors 再然后是祖先交易费
            boost::multi_index::ordered_non_unique<
                boost::multi_index::tag<ancestor_score>,
                boost::multi_index::identity<CTxMemPoolEntry>,
                CompareTxMemPoolEntryByAncestorFee
            >
        >
    > indexed_transaction_set;

    mutable CCriticalSection cs;
    indexed_transaction_set mapTx;

    typedef indexed_transaction_set::nth_index<0>::type::iterator txiter;

    // 所有交易见证数据的　hash
    std::vector<std::pair<uint256, txiter> > vTxHashes; //!< All tx witness hashes/entries in mapTx, in random order

    struct CompareIteratorByHash {
        bool operator()(const txiter &a, const txiter &b) const {
            return a->GetTx().GetHash() < b->GetTx().GetHash();
        }
    };
    typedef std::set<txiter, CompareIteratorByHash> setEntries;

    const setEntries & GetMemPoolParents(txiter entry) const;
    const setEntries & GetMemPoolChildren(txiter entry) const;
private:
    typedef std::map<txiter, setEntries, CompareIteratorByHash> cacheMap;

    struct TxLinks {
        setEntries parents;
        setEntries children;
    };

    typedef std::map<txiter, TxLinks, CompareIteratorByHash> txlinksMap;
    txlinksMap mapLinks;

    void UpdateParent(txiter entry, txiter parent, bool add);
    void UpdateChild(txiter entry, txiter child, bool add);

    std::vector<indexed_transaction_set::const_iterator> GetSortedDepthAndScore() const;

public:
    indirectmap<COutPoint, const CTransaction*> mapNextTx;
    std::map<uint256, CAmount> mapDeltas;

    /** Create a new CTxMemPool.
     * 创建新的　mempool
     */
    explicit CTxMemPool(CBlockPolicyEstimator* estimator = nullptr);

    /**
     * If sanity-checking is turned on, check makes sure the pool is
     * consistent (does not contain two transactions that spend the same inputs,
     * all inputs are in the mapNextTx array). If sanity-checking is turned off,
     * check does nothing.
     *
     * 如果开启了　santiy-check，那么 check 函数将会保证 pool 的一致性,
     * 即不包含双花交易，所有的输入都在 mapNextTx　数组中。
     *
     * 如果关闭了　santi-check，那么 check 函数什么都不做。
     */
    void check(const CCoinsViewCache *pcoins) const;
    void setSanityCheck(double dFrequency = 1.0) { nCheckFrequency = static_cast<uint32_t>(dFrequency * 4294967295.0); }

    // addUnchecked must updated state for all ancestors of a given transaction,
    // to track size/count of descendant transactions.  First version of
    // addUnchecked can be used to have it call CalculateMemPoolAncestors(), and
    // then invoke the second version.
    // Note that addUnchecked is ONLY called from ATMP outside of tests
    // and any other callers may break wallet's in-mempool tracking (due to
    // lack of CValidationInterface::TransactionAddedToMempool callbacks).
    /**
     * addUnchecked　函数必须首先更新交易的祖先交易状态，
     * 第一个addUnchecked函数可以用来调用　CalculateMemPoolAncestors()，
     * 然后调用第二个　addUnchecked
     */
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, bool validFeeEstimate = true);
    bool addUnchecked(const uint256& hash, const CTxMemPoolEntry &entry, setEntries &setAncestors, bool validFeeEstimate = true);

    void removeRecursive(const CTransaction &tx, MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN);
    void removeForReorg(const CCoinsViewCache *pcoins, unsigned int nMemPoolHeight, int flags);
    void removeConflicts(const CTransaction &tx);
    void removeForBlock(const std::vector<CTransactionRef>& vtx, unsigned int nBlockHeight);

    void clear();
    void _clear(); //lock free
    bool CompareDepthAndScore(const uint256& hasha, const uint256& hashb);
    void queryHashes(std::vector<uint256>& vtxid);
    bool isSpent(const COutPoint& outpoint);
    unsigned int GetTransactionsUpdated() const;
    void AddTransactionsUpdated(unsigned int n);

    /**
     * Check that none of this transactions inputs are in the mempool, and thus
     * the tx is not dependent on other mempool transactions to be included in a block.
     * 检查交易的输入是否在当前的 mempool 中
     */
    bool HasNoInputsOf(const CTransaction& tx) const;

    /**
     * Affect CreateNewBlock prioritisation of transactions
     * 调整 CreateNewBlock　时交易的优先级
     * */
    void PrioritiseTransaction(const uint256& hash, const CAmount& nFeeDelta);
    void ApplyDelta(const uint256 hash, CAmount &nFeeDelta) const;
    void ClearPrioritisation(const uint256 hash);

public:
    /** Remove a set of transactions from the mempool.
     *  If a transaction is in this set, then all in-mempool descendants must
     *  also be in the set, unless this transaction is being removed for being
     *  in a block.
     *  Set updateDescendants to true when removing a tx that was in a block, so
     *  that any in-mempool descendants have their ancestor state updated.
     *
     *  从 mempool 中移除一个交易集合，
     *  如果一个交易在这个集合中，那么它的所有子孙交易都必须在集合中，除非该交易已经被打包到区块中。
     *  如果要移除一个已经被打包到区块中的交易，那么要把 updateDescendats 设为 true，从而更新　mempool 中所有子孙节点的祖先信息.
     */
    void RemoveStaged(setEntries &stage, bool updateDescendants, MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN);

    /** When adding transactions from a disconnected block back to the mempool,
     *  new mempool entries may have children in the mempool (which is generally
     *  not the case when otherwise adding transactions).
     *  UpdateTransactionsFromBlock() will find child transactions and update the
     *  descendant state for each transaction in vHashesToUpdate (excluding any
     *  child transactions present in vHashesToUpdate, which are already accounted
     *  for).  Note: vHashesToUpdate should be the set of transactions from the
     *  disconnected block that have been accepted back into the mempool.
     *
     *  从竞争失败的Block中更新交易信息到 mempool
     */
    void UpdateTransactionsFromBlock(const std::vector<uint256> &vHashesToUpdate);

    /** Try to calculate all in-mempool ancestors of entry.
     *  (these are all calculated including the tx itself)
     *  limitAncestorCount = max number of ancestors
     *  limitAncestorSize = max size of ancestors
     *  limitDescendantCount = max number of descendants any ancestor can have
     *  limitDescendantSize = max size of descendants any ancestor can have
     *  errString = populated with error reason if any limits are hit
     *  fSearchForParents = whether to search a tx's vin for in-mempool parents, or
     *    look up parents from mapLinks. Must be true for entries not in the mempool
     *
     *    计算 mempool 中所有 entry 的祖先
     *    limitAncestorCount = 最大祖先数量
     *    limitAncestorSize = 最大祖先交易大小
     *    limitDescendantCount = 任意祖先的最大子孙数量
     *    limitDescendantSize = 任意祖先的最大子孙大小
     *    errString = 超过了任何 limit 限制的错误提示
     *    fSearchForParents = 是否在 mempool 中搜索交易的输入或者从 mapLinks 中查找，对于不在　mempool 中的 entry 必须设为 true
     */
    bool CalculateMemPoolAncestors(const CTxMemPoolEntry &entry, setEntries &setAncestors, uint64_t limitAncestorCount, uint64_t limitAncestorSize, uint64_t limitDescendantCount, uint64_t limitDescendantSize, std::string &errString, bool fSearchForParents = true) const;

    /** Populate setDescendants with all in-mempool descendants of hash.
     *  Assumes that setDescendants includes all in-mempool descendants of anything
     *  already in it.  */
    void CalculateDescendants(txiter it, setEntries &setDescendants);

    /** The minimum fee to get into the mempool, which may itself not be enough
      *  for larger-sized transactions.
      *  The incrementalRelayFee policy variable is used to bound the time it
      *  takes the fee rate to go back down all the way to 0. When the feerate
      *  would otherwise be half of this, it is set to 0 instead.
      *
      *  获取进入　mempool 需要的最小交易费
      *  incrementalRelayFee 变量用来限制 feerate 降到 0 所需的时间.
      */
    CFeeRate GetMinFee(size_t sizelimit) const;

    /** Remove transactions from the mempool until its dynamic size is <= sizelimit.
      *  pvNoSpendsRemaining, if set, will be populated with the list of outpoints
      *  which are not in mempool which no longer have any spends in this mempool.
      *
      *  移除所有动态大小超过 sizelimit 的交易
      *  如果传入了　pvNoSpendsRemaining,　那么将返回不在 mempool 中并且也没有任何输出在 mempool 的交易列表.
      */
    void TrimToSize(size_t sizelimit, std::vector<COutPoint>* pvNoSpendsRemaining=nullptr);

    /** Expire all transaction (and their dependencies) in the mempool older than time. Return the number of removed transactions.
     * 移除所有在 time 之前的交易和它的子孙交易，返回移除的数量
     * */
    int Expire(int64_t time);

    /** Returns false if the transaction is in the mempool and not within the chain limit specified.
     * 如果交易不满足　chain limit, 返回 false
     * */
    bool TransactionWithinChainLimit(const uint256& txid, size_t chainLimit) const;

    unsigned long size()
    {
        LOCK(cs);
        return mapTx.size();
    }

    uint64_t GetTotalTxSize() const
    {
        LOCK(cs);
        return totalTxSize;
    }

    bool exists(uint256 hash) const
    {
        LOCK(cs);
        return (mapTx.count(hash) != 0);
    }

    CTransactionRef get(const uint256& hash) const;
    TxMempoolInfo info(const uint256& hash) const;
    std::vector<TxMempoolInfo> infoAll() const;

    size_t DynamicMemoryUsage() const;

    boost::signals2::signal<void (CTransactionRef)> NotifyEntryAdded;
    boost::signals2::signal<void (CTransactionRef, MemPoolRemovalReason)> NotifyEntryRemoved;

private:
    /** UpdateForDescendants is used by UpdateTransactionsFromBlock to update
     *  the descendants for a single transaction that has been added to the
     *  mempool but may have child transactions in the mempool, eg during a
     *  chain reorg.  setExclude is the set of descendant transactions in the
     *  mempool that must not be accounted for (because any descendants in
     *  setExclude were added to the mempool after the transaction being
     *  updated and hence their state is already reflected in the parent
     *  state).
     *
     *  cachedDescendants will be updated with the descendants of the transaction
     *  being updated, so that future invocations don't need to walk the
     *  same transaction again, if encountered in another transaction chain.
     *
     *  用来更新被加入 pool 中的单个交易的子孙节点.
     *  setExclude 是内存池中不用更新的子孙交易集合.
     *
     *  当子孙交易被更新时， cachedDescendants 也同时更新.
     */
    void UpdateForDescendants(txiter updateIt,
            cacheMap &cachedDescendants,
            const std::set<uint256> &setExclude);

    /** Update ancestors of hash to add/remove it as a descendant transaction. */
    void UpdateAncestorsOf(bool add, txiter hash, setEntries &setAncestors);

    /** Set ancestor state for an entry
     * 设置一个 entry 的祖先
     * */
    void UpdateEntryForAncestors(txiter it, const setEntries &setAncestors);


    /** For each transaction being removed, update ancestors and any direct children.
      * If updateDescendants is true, then also update in-mempool descendants'
      * ancestor state.
      * 对于每一个要移除的交易，更新它的祖先和直接的儿子.
      * 如果 updateDescendants　设为 true，那么还同时更新 mempool 中子孙的祖先状态.
      * */
    void UpdateForRemoveFromMempool(const setEntries &entriesToRemove, bool updateDescendants);


    /** Sever link between specified transaction and direct children. */
    void UpdateChildrenForRemoval(txiter entry);

    /** Before calling removeUnchecked for a given transaction,
     *  UpdateForRemoveFromMempool must be called on the entire (dependent) set
     *  of transactions being removed at the same time.  We use each
     *  CTxMemPoolEntry's setMemPoolParents in order to walk ancestors of a
     *  given transaction that is removed, so we can't remove intermediate
     *  transactions in a chain before we've updated all the state for the
     *  removal.
     *
     *  对应一个特定的交易，调用　removeUnchecked 之前，必须同时为要移除的交易集合调用　updateForRemoveFromMempool。
     * 我们使用每个 CTxMemPoolEntry 中的 setMemPoolParents 来遍历要移除交易的祖先，这样能保证我们更新的正确性.
     */
    void removeUnchecked(txiter entry, MemPoolRemovalReason reason = MemPoolRemovalReason::UNKNOWN);
};

/** 
 * CCoinsView that brings transactions from a mempool into view.
 * It does not check for spendings by memory pool transactions.
 * Instead, it provides access to all Coins which are either unspent in the
 * base CCoinsView, or are outputs from any mempool transaction!
 * This allows transaction replacement to work as expected, as you want to
 * have all inputs "available" to check signatures, and any cycles in the
 * dependency graph are checked directly in AcceptToMemoryPool.
 * It also allows you to sign a double-spend directly in signrawtransaction,
 * as long as the conflicting transaction is not yet confirmed.
 */
class CCoinsViewMemPool : public CCoinsViewBacked
{
protected:
    const CTxMemPool& mempool;

public:
    CCoinsViewMemPool(CCoinsView* baseIn, const CTxMemPool& mempoolIn);
    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
};

/**
 * DisconnectedBlockTransactions

 * During the reorg, it's desirable to re-add previously confirmed transactions
 * to the mempool, so that anything not re-confirmed in the new chain is
 * available to be mined. However, it's more efficient to wait until the reorg
 * is complete and process all still-unconfirmed transactions at that time,
 * since we expect most confirmed transactions to (typically) still be
 * confirmed in the new chain, and re-accepting to the memory pool is expensive
 * (and therefore better to not do in the middle of reorg-processing).
 * Instead, store the disconnected transactions (in order!) as we go, remove any
 * that are included in blocks in the new chain, and then process the remaining
 * still-unconfirmed transactions at the end.
 */

// multi_index tag names
struct txid_index {};
struct insertion_order {};

struct DisconnectedBlockTransactions {
    typedef boost::multi_index_container<
        CTransactionRef,
        boost::multi_index::indexed_by<
            // sorted by txid
            boost::multi_index::hashed_unique<
                boost::multi_index::tag<txid_index>,
                mempoolentry_txid,
                SaltedTxidHasher
            >,
            // sorted by order in the blockchain
            boost::multi_index::sequenced<
                boost::multi_index::tag<insertion_order>
            >
        >
    > indexed_disconnected_transactions;

    // It's almost certainly a logic bug if we don't clear out queuedTx before
    // destruction, as we add to it while disconnecting blocks, and then we
    // need to re-process remaining transactions to ensure mempool consistency.
    // For now, assert() that we've emptied out this object on destruction.
    // This assert() can always be removed if the reorg-processing code were
    // to be refactored such that this assumption is no longer true (for
    // instance if there was some other way we cleaned up the mempool after a
    // reorg, besides draining this object).
    ~DisconnectedBlockTransactions() { assert(queuedTx.empty()); }

    indexed_disconnected_transactions queuedTx;
    uint64_t cachedInnerUsage = 0;

    // Estimate the overhead of queuedTx to be 6 pointers + an allocation, as
    // no exact formula for boost::multi_index_contained is implemented.
    size_t DynamicMemoryUsage() const {
        return memusage::MallocUsage(sizeof(CTransactionRef) + 6 * sizeof(void*)) * queuedTx.size() + cachedInnerUsage;
    }

    void addTransaction(const CTransactionRef& tx)
    {
        queuedTx.insert(tx);
        cachedInnerUsage += RecursiveDynamicUsage(tx);
    }

    // Remove entries based on txid_index, and update memory usage.
    void removeForBlock(const std::vector<CTransactionRef>& vtx)
    {
        // Short-circuit in the common case of a block being added to the tip
        if (queuedTx.empty()) {
            return;
        }
        for (auto const &tx : vtx) {
            auto it = queuedTx.find(tx->GetHash());
            if (it != queuedTx.end()) {
                cachedInnerUsage -= RecursiveDynamicUsage(*it);
                queuedTx.erase(it);
            }
        }
    }

    // Remove an entry by insertion_order index, and update memory usage.
    void removeEntry(indexed_disconnected_transactions::index<insertion_order>::type::iterator entry)
    {
        cachedInnerUsage -= RecursiveDynamicUsage(*entry);
        queuedTx.get<insertion_order>().erase(entry);
    }

    void clear()
    {
        cachedInnerUsage = 0;
        queuedTx.clear();
    }
};

#endif // BITCOIN_TXMEMPOOL_H
