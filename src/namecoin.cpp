#include <vector>
using namespace std;

#include "script.h"
#include "wallet.h"
extern CWallet* pwalletMain;
extern std::map<uint256, CTransaction> mapTransactions;

#include "namecoin.h"
#include "hooks.h"

#include <boost/xpressive/xpressive_dynamic.hpp>

using namespace json_spirit;

template<typename T> void ConvertTo(Value& value, bool fAllowNull=false);

map<vector<unsigned char>, uint256> mapMyNames;
map<vector<unsigned char>, set<uint256> > mapNamePending; // for pending tx

struct nameTempProxy
{
    int nTime;
    vector<unsigned char> vchName;
    int op;
    uint256 hash;
    CNameIndex ind;
};
static vector<nameTempProxy> vNameTemp; // used to store name tx after connectInputs and before connectBlock . TODO: remove this global var and make it local

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

// forward decls
extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet, txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType);
extern void rescanfornames();
extern std::string _(const char* psz);
extern bool ThreadSafeAskFee(int64 nFeeRequired, const std::string& strCaption);

class CNamecoinHooks : public CHooks
{
public:
    virtual bool IsStandardNameTx(CTxDB& txdb, const CTransaction &tx, bool fCheckNameFee);
    virtual bool ConnectInputs(CTxDB& txdb,
            map<uint256, CTxIndex>& mapTestPool,
            const CTransaction& tx,
            vector<CTransaction>& vTxPrev,
            vector<CTxIndex>& vTxindex,
            const CBlockIndex* pindexBlock,
            const CDiskTxPos &txPos,
            bool fBlock,
            bool fMiner);
    virtual bool DisconnectInputs(CTxDB& txdb,
            const CTransaction& tx,
            CBlockIndex* pindexBlock);
    virtual bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    virtual bool DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    virtual bool ExtractAddress(const CScript& script, string& address);
    virtual void AddToPendingNames(const CTransaction& tx);
    virtual bool IsMine(const CTxOut& txout);
    virtual bool IsNameTx(int nVersion);
    virtual bool IsNameScript(CScript scr);
    virtual bool deletePendingName(const CTransaction& tx);
    virtual bool getNameValue(const string& name, string& value);
};

vector<unsigned char> vchFromValue(const Value& value) {
    string strName = value.get_str();
    unsigned char *strbeg = (unsigned char*)strName.c_str();
    return vector<unsigned char>(strbeg, strbeg + strName.size());
}

vector<unsigned char> vchFromString(const string &str) {
    unsigned char *strbeg = (unsigned char*)str.c_str();
    return vector<unsigned char>(strbeg, strbeg + str.size());
}

string stringFromVch(const vector<unsigned char> &vch) {
    string res;
    vector<unsigned char>::const_iterator vi = vch.begin();
    while (vi != vch.end()) {
        res += (char)(*vi);
        vi++;
    }
    return res;
}

// Calculate at which block will expire.
bool CalculateExpiresAt(CNameDB& dbName, const vector<CNameIndex>& vtxPos, int& nExpiresAt)
{
    int64 sum = 0;
    BOOST_FOREACH(const CNameIndex& txPos, vtxPos)
    {
        CTransaction tx;
        if (!tx.ReadFromDisk(txPos.txPos))
            return error("CalculateNameTotalLifeTime() : could not read tx from disk");

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false))
            return error("CalculateNameTotalLifeTime() : not namecoin tx, this should never happen");

        sum += nti.nRentalDays * 175; //days to blocks. 175 is average number of blocks per day
    }

    nExpiresAt = vtxPos.front().nHeight + sum > INT_MAX ? INT_MAX : vtxPos.front().nHeight + sum; //limit to integer value

    return true;
}

//name total lifetime (nTotalLifeTime) and block number at which name was registered (nHeight)
bool GetExpirationData(CNameDB& dbName, const vector<unsigned char> &vchName, int& nTotalLifeTime, int& nHeight)
{
    vector<CNameIndex> vtxPos;
    int nExpiresAt;
    if (!dbName.ExistsName(vchName))
        return error("GetNameTotalLifeTime() : name - %s - does not exist in name DB", stringFromVch(vchName).c_str());
    if (!dbName.ReadName(vchName, vtxPos, nExpiresAt))
        return error("GetNameTotalLifeTime() : failed to read from name DB");

    nHeight = vtxPos.front().nHeight;
    nTotalLifeTime = nExpiresAt - nHeight;

    return true;
}

// Tests if name is active. You can optionaly specify at which height it is/was active.
bool NameActive(CNameDB& dbName, const vector<unsigned char> &vchName, int currentBlockHeight = -1)
{
    vector<CNameIndex> vtxPos;
    int nExpiresAt;
    if (!dbName.ReadName(vchName, vtxPos, nExpiresAt))
        return false;

    if (currentBlockHeight < 0)
        currentBlockHeight = pindexBest->nHeight;

    return currentBlockHeight <= nExpiresAt;
}

bool NameActive(const vector<unsigned char> &vchName, int currentBlockHeight = -1)
{
    CNameDB dbName("r");
    return NameActive(dbName, vchName, currentBlockHeight);
}

//returns minimum name operation fee rounded down to cents
int64 GetNameOpFee(const CBlockIndex* pindexBlock, const int nRentalDays, int op, const vector<unsigned char> &vchName, const vector<unsigned char> &vchValue)
{
    if (op == OP_NAME_DELETE)
        return MIN_TX_FEE;

    const CBlockIndex* lastPoW = GetLastBlockIndex(pindexBlock, false);

    int64 txMinFee = nRentalDays * lastPoW->nMint / (365 * 100); // 1% PoW per 365 days

    if (op == OP_NAME_NEW)
        txMinFee += lastPoW->nMint / 100; // +1% PoW per operation itself

    txMinFee = sqrt(txMinFee / CENT) * CENT; // square root is taken of the number of cents.
    txMinFee += (int)((vchName.size() + vchValue.size()) / 128) * CENT; // 1 cent per 128 bytes

    // Round up to CENT
    txMinFee += CENT - 1;
    txMinFee = (txMinFee / CENT) * CENT;

    // Fee should be at least MIN_TX_FEE
    txMinFee = max(txMinFee, MIN_TX_FEE);
    return txMinFee;

    if (pindexBlock->nHeight < RELEASE_HEIGHT)
        return txMinFee;
    else
    {
        int64 txMinFee2 = 300 * COIN - (pindexBlock->nHeight - RELEASE_HEIGHT) * CENT;
        return txMinFee2 > 0 ? txMinFee + txMinFee2 : txMinFee;
    }
}

bool GetTxPosHeight(const CDiskTxPos& txPos, int& nHeight)
{
    // Read block header
    CBlock block;
    if (!block.ReadFromDisk(txPos.nFile, txPos.nBlockPos, false))
        return false;
    // Find the block in the index
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(block.GetHash());
    if (mi == mapBlockIndex.end())
        return false;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return false;
    nHeight = pindex->nHeight;
    return true;
}

bool RemoveNameScriptPrefix(const CScript& scriptIn, CScript& scriptOut)
{
    NameTxInfo nti;
    CScript::const_iterator pc = scriptIn.begin();

    if (!DecodeNameScript(scriptIn, nti, pc))
        return false;

    scriptOut = CScript(pc, scriptIn.end());
    return true;
}

bool SignNameSignature(const CTransaction& txFrom, CTransaction& txTo, unsigned int nIn, int nHashType=SIGHASH_ALL, CScript scriptPrereq=CScript())
{

    {
        CTxDB txdb("r");
        CTxIndex txInd;
        txdb.ReadTxIndex(txFrom.GetHash(),txInd);
        printf("txFrom depth = %d", txInd.GetDepthInMainChain());
    }


    assert(nIn < txTo.vin.size());
    CTxIn& txin = txTo.vin[nIn];
    assert(txin.prevout.n < txFrom.vout.size());
    const CTxOut& txout = txFrom.vout[txin.prevout.n];

    // Leave out the signature from the hash, since a signature can't sign itself.
    // The checksig op will also drop the signatures from its hash.

    CScript scriptPubKey;
    if (!RemoveNameScriptPrefix(txout.scriptPubKey, scriptPubKey))
        return error("SignNameSignature(): failed to remove name script prefix");

    uint256 hash = SignatureHash(scriptPrereq + txout.scriptPubKey, txTo, nIn, nHashType);

    txnouttype whichType;
    if (!Solver(*pwalletMain, scriptPubKey, hash, nHashType, txin.scriptSig, whichType))
        return false;

    txin.scriptSig = scriptPrereq + txin.scriptSig;

    // Test solution
    if (scriptPrereq.empty())
        if (!VerifyScript(txin.scriptSig, txout.scriptPubKey, txTo, nIn, false, 0))
            return false;

    return true;
}

bool CreateTransactionWithInputTx(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet)
{
    int64 nValue = 0;
    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
    {
        if (nValue < 0)
            return false;
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
        return false;

    wtxNew.BindWallet(pwalletMain);

    {
        LOCK(cs_main);
        // txdb must be opened before the mapWallet lock. EvgenijM86: WHY?
        CTxDB txdb("r");
        {
            LOCK(pwalletMain->cs_wallet);
            {
                nFeeRet = nTransactionFee;
                loop
                {
                    wtxNew.vin.clear();
                    wtxNew.vout.clear();
                    wtxNew.fFromMe = true;

                    int64 nTotalValue = nValue + nFeeRet;
                    printf("CreateTransactionWithInputTx: total value = %d\n", nTotalValue);
                    double dPriority = 0;
                    // vouts to the payees
                    BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
                        wtxNew.vout.push_back(CTxOut(s.second, s.first));

                    int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

                    // Choose coins to use
                    set<pair<const CWalletTx*, unsigned int> > setCoins;
                    int64 nValueIn = 0;
                    printf("CreateTransactionWithInputTx: SelectCoins(%s), nTotalValue = %s, nWtxinCredit = %s\n", FormatMoney(nTotalValue - nWtxinCredit).c_str(), FormatMoney(nTotalValue).c_str(), FormatMoney(nWtxinCredit).c_str());
                    if (nTotalValue - nWtxinCredit > 0)
                    {
                        if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit, wtxNew.nTime, setCoins, nValueIn))
                            return false;
                    }

                    printf("CreateTransactionWithInputTx: selected %d tx outs, nValueIn = %s\n", setCoins.size(), FormatMoney(nValueIn).c_str());

                    vector<pair<const CWalletTx*, unsigned int> > vecCoins(setCoins.begin(), setCoins.end());

                    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
                    {
                        int64 nCredit = coin.first->vout[coin.second].nValue;
                        dPriority += (double)nCredit * coin.first->GetDepthInMainChain();
                    }

                    // Input tx always at first position
                    vecCoins.insert(vecCoins.begin(), make_pair(&wtxIn, nTxOut));

                    nValueIn += nWtxinCredit;
                    dPriority += (double)nWtxinCredit * wtxIn.GetDepthInMainChain();

                    // Fill a vout back to self with any change
                    int64 nChange = nValueIn - nTotalValue;
                    if (nChange >= CENT)
                    {
                        // Note: We use a new key here to keep it from being obvious which side is the change.
                        //  The drawback is that by not reusing a previous key, the change may be lost if a
                        //  backup is restored, if the backup doesn't have the new private key for the change.
                        //  If we reused the old key, it would be possible to add code to look for and
                        //  rediscover unknown transactions that were written with keys of ours to recover
                        //  post-backup change.

                        // Reserve a new key pair from key pool
                        CPubKey vchPubKey = reservekey.GetReservedKey();
                        assert(pwalletMain->HaveKey(vchPubKey.GetID()));

                        // -------------- Fill a vout to ourself, using same address type as the payment
                        // Now sending always to hash160 (GetBitcoinAddressHash160 will return hash160, even if pubkey is used)
                        CScript scriptChange;
                        //NOTE: look at bf798734db4539a39edd6badf54a1c3aecf193e5 commit in src/wallet.cpp
                        //if (vecSend[0].first.GetBitcoinAddressHash160() != 0)
                        //    scriptChange.SetBitcoinAddress(vchPubKey);
                        //else
                         //   scriptChange << vchPubKey << OP_CHECKSIG;
                        scriptChange.SetDestination(vchPubKey.GetID());

                        // Insert change txn at random position:
                        vector<CTxOut>::iterator position = wtxNew.vout.begin()+GetRandInt(wtxNew.vout.size());
                        wtxNew.vout.insert(position, CTxOut(nChange, scriptChange));
                    }
                    else
                        reservekey.ReturnKey();

                    // Fill vin
                    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
                        wtxNew.vin.push_back(CTxIn(coin.first->GetHash(), coin.second));

                    // Sign
                    int nIn = 0;
                    BOOST_FOREACH(PAIRTYPE(const CWalletTx*, unsigned int)& coin, vecCoins)
                    {
                        if (coin.first == &wtxIn && coin.second == nTxOut)
                        {
                            if (!SignNameSignature(*coin.first, wtxNew, nIn++))
                                throw runtime_error("could not sign name coin output");
                        }
                        else
                        {
                            if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
                                return false;
                        }
                    }

                    // Limit size
                    unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                    if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
                        return false;
                    dPriority /= nBytes;

                    // Check that enough fee is included
                    int64 nPayFee = nTransactionFee * (1 + (int64)nBytes / 1000);
                    int64 nMinFee = wtxNew.GetMinFee(1, false);
                    if (nFeeRet < max(nPayFee, nMinFee))
                    {
                        nFeeRet = max(nPayFee, nMinFee);
                        printf("CreateTransactionWithInputTx: re-iterating (nFreeRet = %s)\n", FormatMoney(nFeeRet).c_str());
                        continue;
                    }

                    // Fill vtxPrev by copying from previous transactions vtxPrev
                    wtxNew.AddSupportingTransactions(txdb);
                    wtxNew.fTimeReceivedIsTxTime = true;

                    break;
                }
            }
        }
    }
    printf("CreateTransactionWithInputTx succeeded:\n%s", wtxNew.ToString().c_str());
    return true;
}

// nTxOut is the output from wtxIn that we should grab
// requires cs_main lock
string SendMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew, bool fAskFee)
{
    int nTxOut = IndexOfNameOutput(wtxIn);
    CReserveKey reservekey(pwalletMain);
    int64 nFeeRequired;
    vector< pair<CScript, int64> > vecSend;
    vecSend.push_back(make_pair(scriptPubKey, nValue));

    if (nNetFee)
    {
        CScript scriptFee;
        scriptFee << OP_RETURN;
        vecSend.push_back(make_pair(scriptFee, nNetFee));
    }

    if (!CreateTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew, reservekey, nFeeRequired))
    {
        string strError;
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoney() : %s", strError.c_str());
        return strError;
    }

    if (fAskFee && !ThreadSafeAskFee(nFeeRequired, "Emercoin"))
        return "ABORTED";

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        return _("SendMoneyWithInputTx(): The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

// scans nameindex.dat and return names with their last CNameIndex
bool CNameDB::ScanNames(
        const vector<unsigned char>& vchName,
        int nMax,
        vector<
            pair<
                vector<unsigned char>,
                pair<CNameIndex, int>
            >
        >& nameScan)
{
    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;

    unsigned int fFlags = DB_SET_RANGE;
    loop
    {
        // Read next record
        CDataStream ssKey(SER_DISK, CLIENT_VERSION);
        if (fFlags == DB_SET_RANGE)
            ssKey << make_pair(string("namei"), vchName);
        CDataStream ssValue(SER_DISK, CLIENT_VERSION);
        int ret = ReadAtCursor(pcursor, ssKey, ssValue, fFlags);
        fFlags = DB_NEXT;
        if (ret == DB_NOTFOUND)
            break;
        else if (ret != 0)
            return false;

        // Unserialize
        string strType;
        ssKey >> strType;
        if (strType == "namei")
        {
            vector<unsigned char> vchName;
            ssKey >> vchName;
            pair< vector<CNameIndex>, int > val;
            ssValue >> val;
            CNameIndex txPos;
            if (!val.first.empty())
            {
                txPos = val.first.back();
            }
            nameScan.push_back(make_pair(vchName, make_pair(txPos, val.second)));
        }

        if (nameScan.size() >= nMax)
            break;
    }
    pcursor->close();
    return true;
}

// this sould only be called in nameindex.dat does not exist
bool CNameDB::ReconstructNameIndex()
{
    CTxDB txdb("r");
    CTxIndex txindex;
    CBlockIndex* pindex = pindexGenesisBlock;
    {
        LOCK(pwalletMain->cs_wallet);
        while (pindex)
        {
            CBlock block;
            block.ReadFromDisk(pindex, true);

            BOOST_FOREACH(CTransaction& tx, block.vtx)
            {
                if (tx.nVersion != NAMECOIN_TX_VERSION)
                    continue;

                // posThisTx = txindex.pos
                if(!txdb.ReadTxIndex(tx.GetHash(), txindex))
                    return error("ReconstructNameIndex() : failed to read from disk, aborting.");

                // mapTestPool - is used in hooks->ConnectInput only if we have fMiner=true, so we don't care about it in this case
                map<uint256, CTxIndex> mapTestPool;
                MapPrevTx mapInputs;
                bool fInvalid;
                if (!tx.FetchInputs(txdb, mapTestPool, true, false, mapInputs, fInvalid))
                    return error("ReconstructNameIndex() : failed to read from disk, aborting.");

                // vTxPrev and vTxindex
                vector<CTxIndex> vTxindex;
                vector<CTransaction> vTxPrev;
                for (unsigned int i = 0; i < tx.vin.size(); i++)
                {
                    COutPoint prevout = tx.vin[i].prevout;
                    CTransaction& txPrev = mapInputs[prevout.hash].second;
                    CTxIndex& txindex = mapInputs[prevout.hash].first;

                    vTxPrev.push_back(txPrev);
                    vTxindex.push_back(txindex);
                }
                hooks->ConnectInputs(txdb, mapTestPool, tx, vTxPrev, vTxindex, pindex, txindex.pos, true, false);
            }
            hooks->ConnectBlock(txdb, pindex);
            pindex = pindex->pnext;
        }
    }
    return true;
}


CHooks* InitHook()
{
    return new CNamecoinHooks();
}

// version for connectInputs. Used when accepting blocks.
bool IsNameFeeEnough(CTxDB& txdb, const CTransaction& tx, const NameTxInfo& nti, const CBlockIndex* pindexBlock, const map<uint256, CTxIndex>& mapTestPool, bool fBlock, bool fMiner)
{
// get tx fee
// Note: if fBlock and fMiner equal false then FetchInputs will search mempool
    int64 txFee;
    MapPrevTx mapInputs;
    bool fInvalid = false;
    if (!tx.FetchInputs(txdb, mapTestPool, fBlock, fMiner, mapInputs, fInvalid))
        return false;
    txFee = tx.GetValueIn(mapInputs) - tx.GetValueOut();


// scan last 10 PoW block for tx fee that matches the one specified in tx
    const CBlockIndex* lastPoW = GetLastBlockIndex(pindexBlock, false);
    bool txFeePass = false;
    for (int i = 1; i <= 10; i++)
    {
        int64 netFee = GetNameOpFee(lastPoW, nti.nRentalDays, nti.op, nti.vchName, nti.vchValue);
        //printf("op == name_new, txFee = %"PRI64d", netFee = %"PRI64d", nRentalDays = %d\n", txFee, netFee, nRentalDays);
        if (txFee >= netFee)
        {
            txFeePass = true;
            break;
        }
        lastPoW = GetLastBlockIndex(lastPoW->pprev, false);
    }
    return txFeePass;
}
// version for mempool::accept. Used to check newly submited transaction that has yet to get in a block.
bool IsNameFeeEnough(CTxDB& txdb, const CTransaction& tx, const NameTxInfo& nti)
{
    map<uint256, CTxIndex> unused;
    return IsNameFeeEnough(txdb, tx, nti, pindexBest, unused, false, false);
}

bool CNamecoinHooks::IsStandardNameTx(CTxDB& txdb, const CTransaction &tx, bool fCheckNameFee)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return false;

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
        return false;

    if (fCheckNameFee)
        return IsNameFeeEnough(txdb, tx, nti);

    return true;
}

bool checkNameValues(NameTxInfo& ret)
{
    ret.err_msg = "";
    if (ret.vchName.size() > MAX_NAME_LENGTH)
        ret.err_msg.append("name is too long.\n");

    if (ret.vchValue.size() > MAX_VALUE_LENGTH)
        ret.err_msg.append("value is too long.\n");

    if (ret.op == OP_NAME_NEW && ret.nRentalDays < 1)
        ret.err_msg.append("rental days must be greater than 0.\n");

    if (ret.op == OP_NAME_UPDATE && ret.nRentalDays < 0)
        ret.err_msg.append("rental days must be greater or equal 0.\n");

    if (ret.nRentalDays > MAX_RENTAL_DAYS)
        ret.err_msg.append("rental days value is too large.\n");

    if (ret.err_msg != "")
        return false;
    return true;
}

// read name script and extract: name, value and rentalDays
// optionaly it can extract destination address and check if tx is mine (note: it does not check if address is valid)
bool DecodeNameScript(const CScript& script, NameTxInfo &ret, bool checkValuesCorrectness  /* = true */, bool checkAddressAndIfIsMine  /* = false */)
{
    CScript::const_iterator pc = script.begin();
    return DecodeNameScript(script, ret, pc, checkValuesCorrectness, checkAddressAndIfIsMine);
}

bool DecodeNameScript(const CScript& script, NameTxInfo& ret, CScript::const_iterator& pc, bool checkValuesCorrectness, bool checkAddressAndIfIsMine)
{
    // script structure:
    // (name_new | name_update) << OP_DROP << name << days << OP_2DROP << val1 << val2 << .. << valn << OP_DROP2 << OP_DROP2 << ..<< (OP_DROP2 | OP_DROP) << paytoscripthash
    // or
    // name_delete << OP_DROP << name << OP_DROP << paytoscripthash

    // NOTE: script structure is strict - it must not contain anything else in the midle of it to be a valid name script. It can, however, contain anything else after the correct structure have been read.

    ret.nOut = -1;       //CScript does not have nOut

    // read op
    ret.err_msg = "failed to read op";
    opcodetype opcode;
    if (!script.GetOp(pc, opcode))
        return false;
    if (opcode < OP_1 || opcode > OP_16)
        return false;
    ret.op = opcode - OP_1 + 1;

    if (ret.op != OP_NAME_NEW && ret.op != OP_NAME_UPDATE && ret.op != OP_NAME_DELETE)
        return false;

    ret.err_msg = "failed to read OP_DROP after op_type";
    if (!script.GetOp(pc, opcode))
        return false;
    if (opcode != OP_DROP)
        return false;

    vector<unsigned char> vch;

    // read name
    ret.err_msg = "failed to read name";
    if (!script.GetOp(pc, opcode, vch))
        return false;
    if ((opcode == OP_DROP || opcode == OP_2DROP) || !(opcode >= 0 && opcode <= OP_PUSHDATA4))
        return false;
    ret.vchName = vch;

    // if name_delete - read OP_DROP after name and exit.
    if (ret.op == OP_NAME_DELETE)
    {
        ret.err_msg = "failed to read OP2_DROP in name_delete";
        if (!script.GetOp(pc, opcode))
            return false;
        if (opcode != OP_DROP)
            return false;
        ret.err_msg = "";
        ret.fIsMine = true; // name_delete should be always our transaction.
        return true;
    }

    // read rental days
    ret.err_msg = "failed to read rental days";
    if (!script.GetOp(pc, opcode, vch))
        return false;
    if ((opcode == OP_DROP || opcode == OP_2DROP) || !(opcode >= 0 && opcode <= OP_PUSHDATA4))
        return false;
    ret.nRentalDays = CBigNum(vch).getint();

    // read OP_2DROP after name and rentalDays
    ret.err_msg = "failed to read delimeter d in: name << rental << d << value";
    if (!script.GetOp(pc, opcode))
        return false;
    if (opcode != OP_2DROP)
        return false;

    // read value
    ret.err_msg = "failed to read value";
    int valueSize = 0;
    for (;;)
    {
        if (!script.GetOp(pc, opcode, vch))
            return false;
        if (opcode == OP_DROP || opcode == OP_2DROP)
            break;
        if (!(opcode >= 0 && opcode <= OP_PUSHDATA4))
            return false;
        ret.vchValue.insert(ret.vchValue.end(), vch.begin(), vch.end());
        valueSize++;
    }
    pc--;

    // read next delimiter and move the pc after it
    ret.err_msg = "failed to read correct number of DROP operations after value"; //sucess! we have read name script structure
    int delimiterSize = 0;
    while (opcode == OP_DROP || opcode == OP_2DROP)
    {
        if (!script.GetOp(pc, opcode))
            break;
        if (opcode == OP_2DROP)
            delimiterSize += 2;
        if (opcode == OP_DROP)
            delimiterSize += 1;
    }
    pc--;

    if (valueSize != delimiterSize)
        return false;


    ret.err_msg = "";     //sucess! we have read name script structure without errors!
    if (checkValuesCorrectness)
    {
        if (!checkNameValues(ret))
            return false;
    }

    if (checkAddressAndIfIsMine)
    {
        //read address
        CTxDestination address;
        CScript scriptPubKey(pc, script.end());
        if (!ExtractDestination(scriptPubKey, address))
            ret.strAddress = "";
        ret.strAddress = CBitcoinAddress(address).ToString();

        // check if this is mine destination
        ret.fIsMine = IsMine(*pwalletMain, address);
    }

    return true;
}

//returns first name operation. I.e. name_new from chain like name_new->name_update->name_update->...->name_update
bool GetFirstTxOfName(CNameDB& dbName, const vector<unsigned char> &vchName, CTransaction& tx)
{
    vector<CNameIndex> vtxPos;
    int nExpiresAt;
    if (!dbName.ReadName(vchName, vtxPos, nExpiresAt) || vtxPos.empty())
        return false;
    CNameIndex& txPos = vtxPos.front();

    if (!tx.ReadFromDisk(txPos.txPos))
        return error("GetFirstTxOfName() : could not read tx from disk");
    return true;
}

bool GetLastTxOfName(CNameDB& dbName, const vector<unsigned char> &vchName, CTransaction& tx)
{
    vector<CNameIndex> vtxPos;
    int nExpiresAt;
    if (!dbName.ReadName(vchName, vtxPos, nExpiresAt) || vtxPos.empty())
        return false;
    CNameIndex& txPos = vtxPos.back();

    if (!tx.ReadFromDisk(txPos.txPos))
        return error("GetFirstTxOfName() : could not read tx from disk");
    return true;
}


Value sendtoname(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoname <name> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.01"
            + HelpRequiringPassphrase());

    vector<unsigned char> vchName = vchFromValue(params[0]);
    int64 nAmount = AmountFromValue(params[1]);

    // Wallet comments
    CWalletTx wtx;
    if (params.size() > 2 && params[2].type() != null_type && !params[2].get_str().empty())
        wtx.mapValue["comment"] = params[2].get_str();
    if (params.size() > 3 && params[3].type() != null_type && !params[3].get_str().empty())
        wtx.mapValue["to"]      = params[3].get_str();

    string error;
    CBitcoinAddress address;
    if (!GetNameCurrentAddress(vchName, address, error))
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, error);


    string strError = pwalletMain->SendMoneyToDestination(address.Get(), nAmount, wtx);
    if (strError != "")
        throw JSONRPCError(RPC_WALLET_ERROR, strError);

    Object res;
    res.push_back(Pair("sending to", address.ToString()));
    res.push_back(Pair("transaction", wtx.GetHash().GetHex()));
    return res;
}

bool GetNameCurrentAddress(const vector<unsigned char> &vchName, CBitcoinAddress &address, string &error)
{
    CNameDB dbName("r");
    if (!dbName.ExistsName(vchName))
    {
        error = "Name not found";
        return false;
    }

    CTransaction tx;
    NameTxInfo nti;
    if (!(GetLastTxOfName(dbName, vchName, tx) && DecodeNameTx(tx, nti, false, true)))
    {
        error = "Failed to read/decode last name transaction";
        return false;
    }

    address.SetString(nti.strAddress);
    if (!address.IsValid())
    {
        error = "Name contains invalid address"; // this error should never happen, and if it does - this probably means that client blockchain database is corrupted
        return false;
    }

    if (!NameActive(dbName, vchName))
    {
        stringstream ss;
        ss << "This name have expired. If you still wish to send money to it's last owner you can use this command:\n"
           << "sendtoaddress " << address.ToString() << " <your_amount> ";
        error = ss.str();
        return false;
    }

    return true;
}

bool CNamecoinHooks::IsMine(const CTxOut& txout)
{
    CScript scriptPubKey;
    if (!RemoveNameScriptPrefix(txout.scriptPubKey, scriptPubKey))
        return false;

    CScript scriptSig;
    txnouttype whichType;
    if (!Solver(*pwalletMain, scriptPubKey, 0, 0, scriptSig, whichType))
        return false;
    return true;
}

Value name_list(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "name_list [<name>]\n"
                "list my own names"
                );

    vector<unsigned char> vchNameUniq;
    if (params.size() == 1)
        vchNameUniq = vchFromValue(params[0]);

    map<vector<unsigned char>, NameTxInfo> mapNames, mapPending;
    GetNameList(vchNameUniq, mapNames, mapPending);

    Array oRes;
    BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, NameTxInfo)& item, mapNames)
    {
        Object oName;
        oName.push_back(Pair("name", stringFromVch(item.second.vchName)));
        oName.push_back(Pair("value", stringFromVch(item.second.vchValue)));
        if (item.second.fIsMine == false)
            oName.push_back(Pair("transferred", true));
        oName.push_back(Pair("address", item.second.strAddress));
        oName.push_back(Pair("expires_in", item.second.nExpiresAt - pindexBest->nHeight));
        if (item.second.nExpiresAt - pindexBest->nHeight <= 0)
            oName.push_back(Pair("expired", true));

        oRes.push_back(oName);
    }
    return oRes;
}

// read wallet name txs and extract: name, value, rentalDays, nOut and nExpiresAt
void GetNameList(const vector<unsigned char> &vchNameUniq, map<vector<unsigned char>, NameTxInfo> &mapNames, map<vector<unsigned char>, NameTxInfo> &mapPending)
{
    CNameDB dbName("r");
    LOCK2(cs_main, pwalletMain->cs_wallet);

    // add all names from wallet tx that are in blockchain
    BOOST_FOREACH(PAIRTYPE(const uint256, CWalletTx)& item, pwalletMain->mapWallet)
    {
        NameTxInfo ntiWalllet;
        if (!DecodeNameTx(item.second, ntiWalllet, false, false))
            continue;

        CTransaction tx;
        if (!GetLastTxOfName(dbName, ntiWalllet.vchName, tx))
            continue;

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false, true))
            continue;

        if (vchNameUniq.size() > 0 && vchNameUniq != nti.vchName)
            continue;

        vector<CNameIndex> vtxPos;
        if (!dbName.ReadName(nti.vchName, vtxPos, nti.nExpiresAt))
            continue;

        mapNames[nti.vchName] = nti;
    }

    // add all pending names
    BOOST_FOREACH(PAIRTYPE(const vector<unsigned char>, set<uint256>)& item, mapNamePending)
    {
        if (!item.second.size())
            continue;

        // if there is a set of pending op on a single name - select last one, by nTime
        CTransaction tx;
        tx.nTime = 0;
        bool found = false;
        BOOST_FOREACH(uint256 hash, item.second)
        {
            if (!mempool.exists(hash))
                continue;
            if (mempool.mapTx[hash].nTime > tx.nTime)
            {
                tx = mempool.mapTx[hash];
                found = true;
            }
        }

        if (!found)
            continue;

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false, true))
            continue;

        if (vchNameUniq.size() > 0 && vchNameUniq != nti.vchName)
            continue;

        mapPending[nti.vchName] = nti;
    }
}

Value name_debug(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 1)
        throw runtime_error(
            "name_debug\n"
            "Dump pending transactions id in the debug file.\n");

    printf("Pending:\n----------------------------\n");
    pair<vector<unsigned char>, set<uint256> > pairPending;

    {
        LOCK(cs_main);
        BOOST_FOREACH(pairPending, mapNamePending)
        {
            string name = stringFromVch(pairPending.first);
            printf("%s :\n", name.c_str());
            uint256 hash;
            BOOST_FOREACH(hash, pairPending.second)
            {
                printf("    ");
                if (!pwalletMain->mapWallet.count(hash))
                    printf("foreign ");
                printf("    %s\n", hash.GetHex().c_str());
            }
        }
    }
    printf("----------------------------\n");
    return true;
}

//TODO: name_history, sendtoname

Value name_show(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
            "name_show <name>\n"
            "Show values of a name.\n"
            );

    Object oLastName;
    vector<unsigned char> vchName = vchFromValue(params[0]);
    string name = stringFromVch(vchName);
    {
        LOCK(cs_main);
        vector<CNameIndex> vtxPos;
        int nExpiresAt;
        CNameDB dbName("r");
        if (!dbName.ReadName(vchName, vtxPos, nExpiresAt))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from name DB");

        if (vtxPos.size() < 1)
            throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");

        CDiskTxPos txPos = vtxPos[vtxPos.size() - 1].txPos;
        if (txPos.IsNull())
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from name DB: txPos.IsNull == true");

        CTransaction tx;
        if (!tx.ReadFromDisk(txPos))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from from disk");

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false, true))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to decode name");

        Object oName;
        oName.push_back(Pair("name", name));
        string value = stringFromVch(nti.vchValue);
        oName.push_back(Pair("value", value));
        oName.push_back(Pair("txid", tx.GetHash().GetHex()));
        oName.push_back(Pair("address", nti.strAddress));
        oName.push_back(Pair("expires_in", nExpiresAt - pindexBest->nHeight));
        if (nExpiresAt - pindexBest->nHeight <= 0)
            oName.push_back(Pair("expired", true));
        oLastName = oName;
    }
    return oLastName;
}

Value name_filter(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 5)
        throw runtime_error(
                "name_filter [[[[[regexp] maxage=36000] from=0] nb=0] stat]\n"
                "scan and filter names\n"
                "[regexp] : apply [regexp] on names, empty means all names\n"
                "[maxage] : look in last [maxage] blocks\n"
                "[from] : show results from number [from]\n"
                "[nb] : show [nb] results, 0 means all\n"
                "[stats] : show some stats instead of results\n"
                "name_filter \"\" 5 # list names updated in last 5 blocks\n"
                "name_filter \"^id/\" # list all names from the \"id\" namespace\n"
                "name_filter \"^id/\" 36000 0 0 stat # display stats (number of names) on active names from the \"id\" namespace\n"
                );

    string strRegexp;
    int nFrom = 0;
    int nNb = 0;
    int nMaxAge = 36000;
    bool fStat = false;
    int nCountFrom = 0;
    int nCountNb = 0;


    if (params.size() > 0)
        strRegexp = params[0].get_str();

    if (params.size() > 1)
        nMaxAge = params[1].get_int();

    if (params.size() > 2)
        nFrom = params[2].get_int();

    if (params.size() > 3)
        nNb = params[3].get_int();

    if (params.size() > 4)
        fStat = (params[4].get_str() == "stat" ? true : false);


    CNameDB dbName("r");
    Array oRes;

    vector<unsigned char> vchName;
    vector<pair<vector<unsigned char>, pair<CNameIndex,int> > > nameScan;
    if (!dbName.ScanNames(vchName, 100000000, nameScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    // compile regex once
    using namespace boost::xpressive;
    smatch nameparts;
    sregex cregex = sregex::compile(strRegexp);

    pair<vector<unsigned char>, pair<CNameIndex,int> > pairScan;
    BOOST_FOREACH(pairScan, nameScan)
    {
        string name = stringFromVch(pairScan.first);

        // regexp
        if(strRegexp != "" && !regex_search(name, nameparts, cregex))
            continue;

        CNameIndex txName = pairScan.second.first;

        vector<CNameIndex> vtxPos;
        int nExpiresAt;
        if (!dbName.ReadName(pairScan.first, vtxPos, nExpiresAt))
            continue;

        // max age
        int nHeight = vtxPos.front().nHeight;
        if(nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
            continue;

        // from limits
        nCountFrom++;
        if(nCountFrom < nFrom + 1)
            continue;

        Object oName;
        if (!fStat) {
            oName.push_back(Pair("name", name));

            string value = stringFromVch(txName.vValue);
            oName.push_back(Pair("value", value));

            int nExpiresIn = nExpiresAt - pindexBest->nHeight;
            oName.push_back(Pair("expires_in", nExpiresIn));
            if (nExpiresIn <= 0)
                oName.push_back(Pair("expired", true));
        }
        oRes.push_back(oName);

        nCountNb++;
        // nb limits
        if(nNb > 0 && nCountNb >= nNb)
            break;
    }

    if (fStat)
    {
        Object oStat;
        oStat.push_back(Pair("blocks",    (int)nBestHeight));
        oStat.push_back(Pair("count",     (int)oRes.size()));
        //oStat.push_back(Pair("sha256sum", SHA256(oRes), true));
        return oStat;
    }

    return oRes;
}

Value name_scan(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 2)
        throw runtime_error(
                "name_scan [<start-name>] [<max-returned>]\n"
                "scan all names, starting at start-name and returning a maximum number of entries (default 500)\n"
                );

    vector<unsigned char> vchName;
    int nMax = 500;
    if (params.size() > 0)
    {
        vchName = vchFromValue(params[0]);
    }

    if (params.size() > 1)
    {
        Value vMax = params[1];
        ConvertTo<double>(vMax);
        nMax = (int)vMax.get_real();
    }

    CNameDB dbName("r");
    Array oRes;

    vector<pair<vector<unsigned char>, pair<CNameIndex,int> > > nameScan;
    if (!dbName.ScanNames(vchName, nMax, nameScan))
        throw JSONRPCError(RPC_WALLET_ERROR, "scan failed");

    pair<vector<unsigned char>, pair<CNameIndex,int> > pairScan;
    BOOST_FOREACH(pairScan, nameScan)
    {
        Object oName;
        string name = stringFromVch(pairScan.first);
        oName.push_back(Pair("name", name));

        CNameIndex txName = pairScan.second.first;
        int nExpiresAt    = pairScan.second.second;
        vector<unsigned char> vchValue = txName.vValue;

        string value = stringFromVch(vchValue);
        oName.push_back(Pair("value", value));
        oName.push_back(Pair("expires_in", nExpiresAt - pindexBest->nHeight));
        if (nExpiresAt - pindexBest->nHeight <= 0)
            oName.push_back(Pair("expired", true));

        oRes.push_back(oName);
    }

    return oRes;
}

bool createNameScript(CScript& nameScript, const vector<unsigned char> &vchName, const vector<unsigned char> &vchValue, int nRentalDays, int op, string& err_msg)
{
    if (op == OP_NAME_DELETE)
    {
        nameScript << op << OP_DROP << vchName << OP_DROP;
        return true;
    }


    {
        NameTxInfo nti(vchName, vchValue, nRentalDays, op, -1, err_msg);
        if (!checkNameValues(nti))
        {
            err_msg = nti.err_msg;
            return false;
        }
    }

    vector<unsigned char> vchRentalDays = CBigNum(nRentalDays).getvch();

    //add name and rental days
    nameScript << op << OP_DROP << vchName << vchRentalDays << OP_2DROP;

    // split value in 520 bytes chunks and add it to script
    {
        int nChunks = ceil(vchValue.size() / 520.0);

        for (unsigned int i = 0; i < nChunks; i++)
        {   // insert data
            vector<unsigned char>::const_iterator sliceBegin = vchValue.begin() + i*520;
            vector<unsigned char>::const_iterator sliceEnd = min(vchValue.begin() + (i+1)*520, vchValue.end());
            vector<unsigned char> vchSubValue(sliceBegin, sliceEnd);
            nameScript << vchSubValue;
        }

            //insert end markers
        for (unsigned int i = 0; i < nChunks / 2; i++)
            nameScript << OP_2DROP;
        if (nChunks % 2 != 0)
            nameScript << OP_DROP;
    }
    return true;
}

Value name_new(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "name_new <name> <value> <days>\n"
                "Creates new key->value pair which expires after specified number of days.\n"
                "Cost is square root of (1% of last PoW + 1% per year of last PoW)."
                + HelpRequiringPassphrase());
    vector<unsigned char> vchName = vchFromValue(params[0]);
    vector<unsigned char> vchValue = vchFromValue(params[1]);
    int nRentalDays = params[2].get_int();

    NameTxReturn ret = name_new(vchName, vchValue, nRentalDays);
    if (!ret.ok)
        throw JSONRPCError(ret.err_code, ret.err_msg);
    return ret.hex.GetHex();
}

NameTxReturn name_new(const vector<unsigned char> &vchName,
              const vector<unsigned char> &vchValue,
              const int nRentalDays)
{
    NameTxReturn ret;
    ret.err_code = RPC_INTERNAL_ERROR; //default value
    ret.ok = false;

    CWalletTx wtx;
    wtx.nVersion = NAMECOIN_TX_VERSION;
    stringstream ss;
    CScript scriptPubKey;

    {
        LOCK(cs_main);

        if (mapNamePending.count(vchName) && mapNamePending[vchName].size())
        {
            ss << "there are " << mapNamePending[vchName].size() <<
                  " pending operations on that name, including " <<
                  mapNamePending[vchName].begin()->GetHex().c_str();
            ret.err_msg = ss.str();
            return ret;
        }

        if (NameActive(vchName))
        {
            ret.err_msg = "name_new on an unexpired name";
            return ret;
        }

        EnsureWalletIsUnlocked();

        CPubKey vchPubKey;
        if (!pwalletMain->GetKeyFromPool(vchPubKey, true))
        {
            ret.err_msg = "failed to get key from pool";
            return ret;
        }
        scriptPubKey.SetDestination(vchPubKey.GetID());

        CScript nameScript;
        if (!createNameScript(nameScript, vchName, vchValue, nRentalDays, OP_NAME_NEW, ret.err_msg))
            return ret;

        nameScript += scriptPubKey;

        int64 prevFee = nTransactionFee;
        nTransactionFee = GetNameOpFee(pindexBest, nRentalDays, OP_NAME_NEW, vchName, vchValue);
        string strError = pwalletMain->SendMoney(nameScript, CENT, wtx, false);
        nTransactionFee = prevFee;

        if (strError != "")
        {
            ret.err_code = RPC_WALLET_ERROR;
            ret.err_msg = strError;
            return ret;
        }
    }

    //success! collect info and return
    CTxDestination address;
    if (ExtractDestination(scriptPubKey, address))
    {
        ret.address = CBitcoinAddress(address).ToString();
    }
    ret.hex = wtx.GetHash();
    ret.ok = true;
    return ret;
}

Value name_update(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
                "name_update <name> <value> <days> [<toaddress>]\nUpdate name value, add days to expiration time and possibly transfer a name to diffrent address."
                + HelpRequiringPassphrase());

    vector<unsigned char> vchName = vchFromValue(params[0]);
    vector<unsigned char> vchValue = vchFromValue(params[1]);
    int nRentalDays = params[2].get_int();
    string strAddress = "";
    if (params.size() == 4)
        strAddress = params[3].get_str();
    printf("vchValue.size = %d\n", vchValue.size());

    NameTxReturn ret = name_update(vchName, vchValue, nRentalDays, strAddress);
    if (!ret.ok)
        throw JSONRPCError(ret.err_code, ret.err_msg);
    return ret.hex.GetHex();
}

NameTxReturn name_update(const vector<unsigned char> &vchName,
              const vector<unsigned char> &vchValue,
              const int nRentalDays,
              string strAddress)
{
    NameTxReturn ret;
    ret.err_code = RPC_INTERNAL_ERROR; //default value
    ret.ok = false;

    CWalletTx wtx;
    wtx.nVersion = NAMECOIN_TX_VERSION;
    stringstream ss;
    CScript scriptPubKey;

    {
    //4 checks - pending operations, name exist?, name is yours?, name expired?
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if (mapNamePending.count(vchName) && mapNamePending[vchName].size())
        {
            ss << "there are " << mapNamePending[vchName].size() <<
                  " pending operations on that name, including " <<
                  mapNamePending[vchName].begin()->GetHex().c_str();
            ret.err_msg = ss.str();
            return ret;
        }

        CNameDB dbName("r");
        CTransaction tx; //we need to select last input
        if (!GetLastTxOfName(dbName, vchName, tx))
        {
            ret.err_msg = "could not find a coin with this name";
            return ret;
        }

        uint256 wtxInHash = tx.GetHash();
        if (!pwalletMain->mapWallet.count(wtxInHash))
        {
            ss << "this coin is not in your wallet: " << wtxInHash.GetHex().c_str();
            ret.err_msg = ss.str();
            return ret;
        }
        else
        {
            CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
            int nTxOut = IndexOfNameOutput(wtxIn);

            if (!hooks->IsMine(wtxIn.vout[nTxOut]))
            {
                ss << "this name is not yours: " << wtxInHash.GetHex().c_str();
                ret.err_msg = ss.str();
                return ret;
            }

            // check if prev output is spent
            {
                CTxDB txdb("r");
                CTxIndex txindex;

                if (!txdb.ReadTxIndex(wtxIn.GetHash(), txindex) ||
                    !txindex.vSpent[nTxOut].IsNull())
                {
                    ss << "Last tx of this name was spent by non-namecoin tx. This means that this name cannot be updated anymore - you will have to wait until it expires:\n"
                       << wtxInHash.GetHex().c_str();
                    ret.err_msg = ss.str();
                    return ret;
                }
            }

            if (!NameActive(dbName, vchName))
            {
                ret.err_msg = "name_update on an expired name";
                return ret;
            }
        }

    //form script and send
        if (strAddress != "")
        {
            CBitcoinAddress address(strAddress);
            if (!address.IsValid())
            {
                ret.err_code = RPC_INVALID_ADDRESS_OR_KEY;
                ret.err_msg = "emercoin address is invalid";
                return ret;
            }
            scriptPubKey.SetDestination(address.Get());
        }
        else
        {
            CPubKey vchPubKey;
            if(!pwalletMain->GetKeyFromPool(vchPubKey, true))
            {
                ret.err_msg = "failed to get key from pool";
                return ret;
            }
            scriptPubKey.SetDestination(vchPubKey.GetID());
        }

        CScript nameScript;
        if (!createNameScript(nameScript, vchName, vchValue, nRentalDays, OP_NAME_UPDATE, ret.err_msg))
            return ret;

        nameScript += scriptPubKey;

        EnsureWalletIsUnlocked();

        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];

        int64 prevFee = nTransactionFee;
        nTransactionFee = GetNameOpFee(pindexBest, nRentalDays, OP_NAME_UPDATE, vchName, vchValue);
        string strError = SendMoneyWithInputTx(nameScript, CENT, 0, wtxIn, wtx, false);
        nTransactionFee = prevFee;

        if (strError != "")
        {
            ret.err_code = RPC_WALLET_ERROR;
            ret.err_msg = strError;
            return ret;
        }
    }

    //success! collect info and return
    CTxDestination address;
    ret.address = "";
    if (ExtractDestination(scriptPubKey, address))
    {
        ret.address = CBitcoinAddress(address).ToString();
    }
    ret.hex = wtx.GetHash();
    ret.ok = true;
    return ret;
}

Value name_delete(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 1)
        throw runtime_error(
                "name_delete <name>\nDelete a name if you own it. Others may do name_new after this command."
                + HelpRequiringPassphrase());

    vector<unsigned char> vchName = vchFromValue(params[0]);

    NameTxReturn ret = name_delete(vchName);
    if (!ret.ok)
        throw JSONRPCError(ret.err_code, ret.err_msg);
    return ret.hex.GetHex();

}

//TODO: finish name_delete
NameTxReturn name_delete(const vector<unsigned char> &vchName)
{
    NameTxReturn ret;
    ret.err_code = RPC_INTERNAL_ERROR; //default value
    ret.ok = false;

    CWalletTx wtx;
    wtx.nVersion = NAMECOIN_TX_VERSION;
    stringstream ss;
    CScript scriptPubKey;

    {
    //4 checks - pending operations, name exist?, name is yours?, name expired?
        LOCK2(cs_main, pwalletMain->cs_wallet);

        if (mapNamePending.count(vchName) && mapNamePending[vchName].size())
        {
            ss << "there are " << mapNamePending[vchName].size() <<
                  " pending operations on that name, including " <<
                  mapNamePending[vchName].begin()->GetHex().c_str();
            ret.err_msg = ss.str();
            return ret;
        }

        CNameDB dbName("r");
        CTransaction tx; //we need to select last input
        if (!GetLastTxOfName(dbName, vchName, tx))
        {
            ret.err_msg = "could not find a coin with this name";
            return ret;
        }

        uint256 wtxInHash = tx.GetHash();
        if (!pwalletMain->mapWallet.count(wtxInHash))
        {
            ss << "this coin is not in your wallet: " << wtxInHash.GetHex().c_str();
            ret.err_msg = ss.str();
            return ret;
        }
        else
        {
            CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];
            int nTxOut = IndexOfNameOutput(wtxIn);

            if (!hooks->IsMine(wtxIn.vout[nTxOut]))
            {
                ss << "this name is not yours: " << wtxInHash.GetHex().c_str();
                ret.err_msg = ss.str();
                return ret;
            }

            // check if prev output is spent
            {
                CTxDB txdb("r");
                CTxIndex txindex;

                if (!txdb.ReadTxIndex(wtxIn.GetHash(), txindex) ||
                    !txindex.vSpent[nTxOut].IsNull())
                {
                    ss << "Last tx of this name was spent by non-namecoin tx. This means that this name cannot be updated anymore - you will have to wait until it expires:\n"
                       << wtxInHash.GetHex().c_str();
                    ret.err_msg = ss.str();
                    return ret;
                }
            }

            if (!NameActive(dbName, vchName))
            {
                ret.err_msg = "name_delete on an expired name";
                return ret;
            }
        }

    //form script and send
        CPubKey vchPubKey;
        if(!pwalletMain->GetKeyFromPool(vchPubKey, true))
        {
            ret.err_msg = "failed to get key from pool";
            return ret;
        }
        scriptPubKey.SetDestination(vchPubKey.GetID());

        CScript nameScript;
        {
            vector<unsigned char> vchValue;
            int nDays = 0;
            createNameScript(nameScript, vchName, vchValue, nDays, OP_NAME_DELETE, ret.err_msg); //this should never fail for name_delete
        }

        nameScript += scriptPubKey;

        EnsureWalletIsUnlocked();

        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];

        string strError = SendMoneyWithInputTx(nameScript, CENT, 0, wtxIn, wtx, false);

        if (strError != "")
        {
            ret.err_code = RPC_WALLET_ERROR;
            ret.err_msg = strError;
            return ret;
        }
    }

    //success! collect info and return
    CTxDestination address;
    ret.address = "";
    if (ExtractDestination(scriptPubKey, address))
    {
        ret.address = CBitcoinAddress(address).ToString();
    }
    ret.hex = wtx.GetHash();
    ret.ok = true;
    return ret;
}

void rescanfornames()
{
    printf("Scanning blockchain for names to create fast index...\n");

    CNameDB dbName("cr+");

    // scan blockchain
    dbName.ReconstructNameIndex();
}

// Check that the last entry in name history matches the given tx pos
bool CheckNameTxPos(const vector<CNameIndex> &vtxPos, const CDiskTxPos& txPos)
{
    if (vtxPos.empty())
        return false;

    return vtxPos.back().txPos == txPos;
}

// read name tx and extract: name, value and rentalDays
// optionaly it can extract destination address and check if tx is mine (note: it does not check if address is valid)
bool DecodeNameTx(const CTransaction& tx, NameTxInfo& nti, bool checkValuesCorrectness /* = true */, bool checkAddressAndIfIsMine /* = false */)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return false;

    bool found = false;
    for (int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& out = tx.vout[i];
        if (DecodeNameScript(out.scriptPubKey, nti, checkValuesCorrectness, checkAddressAndIfIsMine))
        {
            // If more than one name op, fail
            if (found)
                return false;

            nti.nOut = i;
            found = true;
        }
    }

    return found;
}

int IndexOfNameOutput(const CTransaction& tx)
{
    NameTxInfo nti;
    bool good = DecodeNameTx(tx, nti);

    if (!good)
        throw runtime_error("IndexOfNameOutput() : name output not found");
    return nti.nOut;
}

void CNamecoinHooks::AddToPendingNames(const CTransaction& tx)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return;

    if (tx.vout.size() < 1)
    {
        error("AcceptToMemoryPool() : no output in tx %s\n", tx.ToString().c_str());
        return;
    }

    NameTxInfo nti;
    bool good = DecodeNameTx(tx, nti);

    if (!good)
    {
        error("AcceptToMemoryPool() : could not decode name script in tx %s", tx.ToString().c_str());
        return;
    }

    {
        LOCK(cs_main);
        mapNamePending[nti.vchName].insert(tx.GetHash());
    }
}


bool ConnectInputsInner(CTxDB& txdb,
        map<uint256, CTxIndex>& mapTestPool,
        const CTransaction& tx,
        vector<CTransaction>& vTxPrev, //vector of all input transactions
        vector<CTxIndex>& vTxindex,
        const CBlockIndex* pindexBlock,
        const CDiskTxPos& txPos,
        bool fBlock,
        bool fMiner)
{
    // find prev name tx
    int nInput = 0;
    bool found = false;
    NameTxInfo prev_nti;
    for (int i = 0; i < tx.vin.size(); i++) //this scans all scripts of tx.vin
    {
        CTxOut& out = vTxPrev[i].vout[tx.vin[i].prevout.n];

        if (DecodeNameScript(out.scriptPubKey, prev_nti))
        {
            if (found)
                return error("ConnectInputHook() : multiple previous name transactions in %s", tx.GetHash().GetHex().c_str());
            found = true;
            nInput = i;
        }
    }

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
    {
        if (pindexBlock->nHeight > RELEASE_HEIGHT)
            return error("ConnectInputsHook() : could not decode a namecoin tx - %s", tx.GetHash().GetHex().c_str());
        return false;
    }

    vector<unsigned char> vchName = nti.vchName;
    string sName = stringFromVch(vchName);
    vector<unsigned char> vchValue = nti.vchValue;

    if (fMiner)
    {
        // Check that no other pending txs on this name are already in the block to be mined
        // TODO: this should be done while accepting tx to memory pool
        set<uint256>& setPending = mapNamePending[vchName];
        BOOST_FOREACH(const PAIRTYPE(uint256, CTxIndex)& s, mapTestPool)
        {
            if (setPending.count(s.first))
                return error("ConnectInputsHook() : will not mine name %s in tx %s because it clashes with tx %s", sName.c_str(), tx.GetHash().GetHex().c_str(), s.first.GetHex().c_str());
        }
    }

    if (GetBoolArg("-printNamecoinConnectInputs"))
        printf("name = %s, value = %s, fBlock = %d, fMiner = %d, hex = %s\n", sName.c_str(), stringFromVch(vchValue).c_str(), fBlock, fMiner, tx.GetHash().GetHex().c_str());

    CNameDB dbName("r");

    switch (nti.op)
    {
        case OP_NAME_NEW:
        {
            //scan last 10 PoW block for tx fee that matches the one specified in tx
            if (!IsNameFeeEnough(txdb, tx, nti, pindexBlock, mapTestPool, fBlock, fMiner))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("ConnectInputsHook() : rejected name_new %s in tx %s because not enough fee.", sName.c_str(), tx.GetHash().GetHex().c_str());
                return false;
            }

            if (NameActive(dbName, vchName, pindexBlock->nHeight))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("ConnectInputsHook() : name_new on an unexpired name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());
                return false;
            }
            break;
        }
        case OP_NAME_UPDATE:
        {
            //scan last 10 PoW block for tx fee that matches the one specified in tx
            if (!IsNameFeeEnough(txdb, tx, nti, pindexBlock, mapTestPool, fBlock, fMiner))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("ConnectInputsHook() : rejected name_update %s in tx %s because not enough fee.", sName.c_str(), tx.GetHash().GetHex().c_str());
                return false;
            }

            if (!found || (prev_nti.op != OP_NAME_NEW && prev_nti.op != OP_NAME_UPDATE))
                return error("name_update without previous new or update tx, for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

            if (prev_nti.vchName != vchName)
                return error("ConnectInputsHook() : name_update name mismatch for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

            if (!NameActive(dbName, vchName, pindexBlock->nHeight))
                return error("ConnectInputsHook() : name_update on an unexpired name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());
            break;
        }
        case OP_NAME_DELETE:
        {
            if (!found || (prev_nti.op != OP_NAME_NEW && prev_nti.op != OP_NAME_UPDATE))
                return error("name_delete without previous new or update tx, for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

            if (prev_nti.vchName != vchName)
                return error("ConnectInputsHook() : name_delete name mismatch for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

            if (!NameActive(dbName, vchName, pindexBlock->nHeight))
                return error("ConnectInputsHook() : name_delete on expired name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());
            break;
        }
        default:
            return error("ConnectInputsHook() : name %s in tx %s has unknown name operation", sName.c_str(), tx.GetHash().GetHex().c_str());
    }

    vector<CNameIndex> vtxPos;
    int nExpiresAt;
    if (dbName.ExistsName(vchName) && !dbName.ReadName(vchName, vtxPos, nExpiresAt))
        return error("ConnectInputsHook() : failed to read from name DB for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

    if ((nti.op == OP_NAME_UPDATE || nti.op == OP_NAME_DELETE) && !CheckNameTxPos(vtxPos, vTxindex[nInput].pos))
    {
        if (pindexBlock->nHeight > RELEASE_HEIGHT)
            return error("ConnectInputsHook() : name %s in tx %s rejected, since previous tx (%s) is not in the name DB\n", sName.c_str(), tx.GetHash().ToString().c_str(), vTxPrev[nInput].GetHash().ToString().c_str());
        return false;
    }

    // all checks passed - record tx information to vNameTemp. It will be sorted by nTime and writen to nameindex.dat at the end of ConnectBlock
    if (fBlock)
    {
        CNameIndex txPos2;
        txPos2.nHeight = pindexBlock->nHeight;
        txPos2.vValue = vchValue;
        txPos2.txPos = txPos;

        nameTempProxy tmp;
        tmp.nTime = tx.nTime;
        tmp.vchName = vchName;
        tmp.op = nti.op;
        tmp.hash = tx.GetHash();
        tmp.ind = txPos2;

        vNameTemp.push_back(tmp);
    }
    return true;
}

// Returns true if tx is a valid namecoin tx.
// Will write to nameindex.dat if fBlock=true.
// Will remove incorrect namecoin tx or non-namecoin tx that tries to spend namecoin inputs from wallet and memory pool if fMiner=true. TODO: this should be done elsewhere (perhaps at mempool.accept)
bool CNamecoinHooks::ConnectInputs(CTxDB& txdb,
        map<uint256, CTxIndex>& mapTestPool,
        const CTransaction& tx,
        vector<CTransaction>& vTxPrev, //vector of all input transactions
        vector<CTxIndex>& vTxindex,
        const CBlockIndex* pindexBlock,
        const CDiskTxPos& txPos,
        bool fBlock,
        bool fMiner)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return false;

    if (!ConnectInputsInner(txdb, mapTestPool, tx, vTxPrev, vTxindex, pindexBlock, txPos, fBlock, fMiner) && fMiner == true)
    {
        NameTxInfo nti;
        if (DecodeNameTx(tx, nti, false))
        {
            std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi = mapNamePending.find(nti.vchName);
            if (mi != mapNamePending.end())
                mi->second.erase(tx.GetHash());
            if (mi->second.empty())
                mapNamePending.erase(nti.vchName);
        }

        //name TX is invalid - remove it.
        LOCK2(cs_main, pwalletMain->cs_wallet);
        pwalletMain->EraseFromWallet(tx.GetHash());
        mempool.remove(tx);

        return false;
    }

    return true;
}

bool CNamecoinHooks::DisconnectInputs(CTxDB& txdb,
        const CTransaction& tx,
        CBlockIndex* pindexBlock)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return true;

    NameTxInfo nti;
    bool good = DecodeNameTx(tx, nti);
    if (!good)
        return error("DisconnectInputsHook() : could not decode namecoin tx");
    if (nti.op == OP_NAME_NEW || nti.op == OP_NAME_UPDATE)
    {
        CNameDB dbName("cr+");

        dbName.TxnBegin();

        //vector<CDiskTxPos> vtxPos;
        vector<CNameIndex> vtxPos;
        int nExpiresAt;
        if (!dbName.ReadName(nti.vchName, vtxPos, nExpiresAt))
            return error("DisconnectInputsHook() : failed to read from name DB");
        // vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
        // be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
        if (vtxPos.size())
        {
            CTxIndex txindex;
            if (!txdb.ReadTxIndex(tx.GetHash(), txindex))
                return error("DisconnectInputsHook() : failed to read tx index");

            if (vtxPos.back().txPos == txindex.pos)
                vtxPos.pop_back();

            // TODO validate that the first pos is the current tx pos
        }
        if (!CalculateExpiresAt(dbName, vtxPos, nExpiresAt))
            return error("DisconnectInputsHook() : failed to calculate expiration time before writing to name DB");
        if (!dbName.WriteName(nti.vchName, vtxPos, nExpiresAt))
            return error("DisconnectInputsHook() : failed to write to name DB");

        dbName.TxnCommit();
    }

    return true;
}

static string nameFromOp(int op)
{
    switch (op)
    {
        case OP_NAME_UPDATE:
            return "name_update";
        case OP_NAME_NEW:
            return "name_new";
        case OP_NAME_DELETE:
            return "name_delete";
        default:
            return "<unknown name op>";
    }
}

bool CNamecoinHooks::ExtractAddress(const CScript& script, string& address)
{
    NameTxInfo nti;
    if (!DecodeNameScript(script, nti))
        return false;

    string strOp = nameFromOp(nti.op);
    address = strOp + ": " + stringFromVch(nti.vchName);
    return true;
}

bool mycompare (const nameTempProxy &lhs, const nameTempProxy &rhs)
{
    return lhs.nTime < rhs.nTime;
}
// called at end of connecting block
bool CNamecoinHooks::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    if (vNameTemp.empty())
        return true;

    // sort by nTime
    std::sort(vNameTemp.begin(), vNameTemp.end(), mycompare);

    CNameDB dbName("cr+");

    // All of these changes should succed. If there is an error - nameindex.dat is probably corrupt.
    BOOST_FOREACH(const nameTempProxy &i, vNameTemp)
    {
        vector<CNameIndex> vtxPos;
        int nExpiresAt;
        if (dbName.ExistsName(i.vchName) && !dbName.ReadName(i.vchName, vtxPos, nExpiresAt))
            return error("ConnectInputsHook() : failed to read from name DB");

        // try to write changes to NameDB
        dbName.TxnBegin();
        if (i.op == OP_NAME_NEW || i.op == OP_NAME_DELETE)
        {//try to delete previous chain of new->update->update->... from nameindex.dat
            if (!dbName.EraseName(i.vchName))
                return error("ConnectInputsHook() : failed to erase name after name_delete");
            vtxPos.clear();
        }
        if (i.op == OP_NAME_NEW || i.op == OP_NAME_UPDATE)
        {
            vtxPos.push_back(i.ind); // fin add
            if (!CalculateExpiresAt(dbName, vtxPos, nExpiresAt))
                return error("ConnectInputsHook() : failed to calculate expiration time before writing to name DB");
            if (!dbName.WriteName(i.vchName, vtxPos, nExpiresAt))
                return error("ConnectInputsHook() : failed to write to name DB");
            printf("connectInputs(): writing %s to nameindex.dat\n", stringFromVch(i.vchName).c_str());
        }
        {
            LOCK(cs_main);
            map<vector<unsigned char>, set<uint256> >::iterator mi = mapNamePending.find(i.vchName);
            if (mi != mapNamePending.end())
            {
                mi->second.erase(i.hash);
                if (mi->second.empty())
                    mapNamePending.erase(i.vchName);
            }
        }
        if (!dbName.TxnCommit())
            return error("failed to write %s to name DB", stringFromVch(i.vchName).c_str());
    }
    vNameTemp.clear();

    return true;
}

bool CNamecoinHooks::DisconnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    return true;
}

bool CNamecoinHooks::IsNameTx(int nVersion)
{
    return nVersion == NAMECOIN_TX_VERSION;
}

bool CNamecoinHooks::IsNameScript(CScript scr)
{
    NameTxInfo nti;
    return DecodeNameScript(scr, nti, false);
}

bool CNamecoinHooks::deletePendingName(const CTransaction& tx)
{
    NameTxInfo nti;
    if (DecodeNameTx(tx, nti, false) && mapNamePending.count(nti.vchName))
    {
        mapNamePending[nti.vchName].erase(tx.GetHash());
        if (mapNamePending[nti.vchName].empty())
            mapNamePending.erase(nti.vchName);
        return true;
    }
    else
    {
        return false;
    }
}

bool CNamecoinHooks::getNameValue(const string& name, string& value)
{
    vector<unsigned char> vchName = vchFromString(name);
    CNameDB dbName("r");
    if (!dbName.ExistsName(vchName))
        return false;

    CTransaction tx;
    NameTxInfo nti;
    if (!(GetLastTxOfName(dbName, vchName, tx) && DecodeNameTx(tx, nti, false, true)))
        return false;

    if (!NameActive(dbName, vchName))
        return false;

    value = stringFromVch(nti.vchValue);

    return true;
}
