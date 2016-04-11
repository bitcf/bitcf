#include <vector>
using namespace std;

#include "script.h"
#include "wallet.h"
extern CWallet* pwalletMain;
extern std::map<uint256, CTransaction> mapTransactions;

#include "namecoin.h"
#include "hooks.h"

#include <boost/xpressive/xpressive_dynamic.hpp>
#include <boost/lexical_cast.hpp>
#include <fstream>

using namespace json_spirit;

template<typename T> void ConvertTo(Value& value, bool fAllowNull=false);

map<vector<unsigned char>, uint256> mapMyNames;
map<vector<unsigned char>, set<uint256> > mapNamePending; // for pending tx

extern uint256 SignatureHash(CScript scriptCode, const CTransaction& txTo, unsigned int nIn, int nHashType);

// forward decls
extern bool Solver(const CKeyStore& keystore, const CScript& scriptPubKey, uint256 hash, int nHashType, CScript& scriptSigRet, txnouttype& whichTypeRet);
extern bool VerifyScript(const CScript& scriptSig, const CScript& scriptPubKey, const CTransaction& txTo, unsigned int nIn, bool fValidatePayToScriptHash, int nHashType);
extern std::string _(const char* psz);

class CNamecoinHooks : public CHooks
{
public:
    virtual bool IsNameFeeEnough(CTxDB& txdb, const CTransaction &tx);
    virtual bool DisconnectInputs(const CTransaction& tx);
    virtual bool ConnectBlock(CTxDB& txdb, CBlockIndex* pindex);
    virtual bool ExtractAddress(const CScript& script, string& address);
    virtual void AddToPendingNames(const CTransaction& tx);
    virtual bool IsMine(const CTxOut& txout);
    virtual bool IsNameTx(int nVersion);
    virtual bool IsNameScript(CScript scr);
    virtual bool deletePendingName(const CTransaction& tx);
    virtual bool getNameValue(const string& name, string& value);
    virtual bool DumpToTextFile();
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

string limitString(const string& inp, unsigned int size, string message = "")
{
    if (size == -1)
        return inp;

    string ret = inp;
    if (inp.size() > size)
    {
        ret.resize(size);
        ret += message;
    }

    return ret;
}

// Calculate at which block will expire.
bool CalculateExpiresAt(CNameRecord& nameRec)
{
    if (nameRec.deleted())
    {
        nameRec.nExpiresAt = 0;
        return true;
    }

    int64 sum = 0;
    for(unsigned int i = nameRec.nLastActiveChainIndex; i < nameRec.vtxPos.size(); i++)
    {
        CTransaction tx;
        if (!tx.ReadFromDisk(nameRec.vtxPos[i].txPos))
            return error("CalculateExpiresAt() : could not read tx from disk");

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false))
            return error("CalculateExpiresAt() : %s is not namecoin tx, this should never happen", tx.GetHash().GetHex().c_str());

        sum += nti.nRentalDays * 175; //days to blocks. 175 is average number of blocks per day
    }

    //limit to INT_MAX value
    sum += nameRec.vtxPos[nameRec.nLastActiveChainIndex].nHeight;
    nameRec.nExpiresAt = sum > INT_MAX ? INT_MAX : sum;

    return true;
}

// Tests if name is active. You can optionaly specify at which height it is/was active.
bool NameActive(CNameDB& dbName, const vector<unsigned char> &vchName, int currentBlockHeight = -1)
{
    CNameRecord nameRec;
    if (!dbName.ReadName(vchName, nameRec))
        return false;

    if (currentBlockHeight < 0)
        currentBlockHeight = pindexBest->nHeight;

    if (nameRec.deleted()) // last name op was name_delete
        return false;

    return currentBlockHeight <= nameRec.nExpiresAt;
}

bool NameActive(const vector<unsigned char> &vchName, int currentBlockHeight = -1)
{
    CNameDB dbName("r");
    return NameActive(dbName, vchName, currentBlockHeight);
}

// Returns minimum name operation fee rounded down to cents. Should be used during|before transaction creation.
// If you wish to calculate if fee is enough - use IsNameFeeEnough() function.
// Generaly:  GetNameOpFee() > IsNameFeeEnough().
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

// Just like CreateTransaction, but with addition of having 1 input already addded.
bool CreateTransactionWithInputTx(const vector<pair<CScript, int64> >& vecSend, CWalletTx& wtxIn, int nTxOut, CWalletTx& wtxNew, CReserveKey& reservekey, int64& nFeeRet, string& strFailReason)
{
    int64 nValue = 0;
    BOOST_FOREACH (const PAIRTYPE(CScript, int64)& s, vecSend)
    {
        if (nValue < 0)
        {
            strFailReason = _("Transaction amounts must be positive");
            return false;
        }
        nValue += s.second;
    }
    if (vecSend.empty() || nValue < 0)
    {
        strFailReason = _("Transaction amounts must be positive");
        return false;
    }

    wtxNew.BindWallet(pwalletMain);

    {
        CTxDB txdb("r");
        LOCK2(cs_main, pwalletMain->cs_wallet);
        {
            nFeeRet = nTransactionFee;
            loop
            {
                wtxNew.vin.clear();
                wtxNew.vout.clear();
                wtxNew.fFromMe = true;

                int64 nTotalValue = nValue + nFeeRet;
                double dPriority = 0;
                // vouts to the payees
                BOOST_FOREACH(const PAIRTYPE(CScript, int64)& s, vecSend)
                    wtxNew.vout.push_back(CTxOut(s.second, s.first));

                int64 nWtxinCredit = wtxIn.vout[nTxOut].nValue;

                // Choose coins to use
                set<pair<const CWalletTx*, unsigned int> > setCoins;
                int64 nValueIn = 0;
                if (nTotalValue - nWtxinCredit > 0)
                    if (!pwalletMain->SelectCoins(nTotalValue - nWtxinCredit, wtxNew.nTime, setCoins, nValueIn))
                    {
                        strFailReason = _("Insufficient funds");
                        return false;
                    }

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
                        {
                            strFailReason = _("Signing name input failed");
                            return false;
                        }
                    }
                    else
                    {
                        if (!SignSignature(*pwalletMain, *coin.first, wtxNew, nIn++))
                        {
                            strFailReason = _("Signing transaction failed");
                            return false;
                        }
                    }
                }

                // Limit size
                unsigned int nBytes = ::GetSerializeSize(*(CTransaction*)&wtxNew, SER_NETWORK, PROTOCOL_VERSION);
                if (nBytes >= MAX_BLOCK_SIZE_GEN/5)
                {
                    strFailReason = _("Transaction too large");
                    return false;
                }
                dPriority /= nBytes;

                // Check that enough fee is included (at least MIN_TX_FEE per 1000 bytes)
                int64 nPayFee = max(nTransactionFee, MIN_TX_FEE * (1 + (int64)nBytes / 1000));
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
    return true;
}

// nTxOut is the output from wtxIn that we should grab
// requires cs_main lock
string SendMoneyWithInputTx(CScript scriptPubKey, int64 nValue, int64 nNetFee, CWalletTx& wtxIn, CWalletTx& wtxNew)
{
    if (fWalletUnlockMintOnly)
    {
        string strError = _("Error: Wallet unlocked for block minting only, unable to create transaction.");
        printf("SendMoneyWithInputTx(): %s", strError.c_str());
        return strError;
    }

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

    string failReason;
    if (!CreateTransactionWithInputTx(vecSend, wtxIn, nTxOut, wtxNew, reservekey, nFeeRequired, failReason))
    {
        string strError;
        if (nValue + nFeeRequired > pwalletMain->GetBalance())
            strError = strprintf(_("Error: This transaction requires a transaction fee of at least %s because of its amount, complexity, or use of recently received funds "), FormatMoney(nFeeRequired).c_str());
        else
            strError = _("Error: Transaction creation failed  ");
        printf("SendMoneyWithInputTx(): %s", strError.c_str());
        return strError;
    }

    if (!pwalletMain->CommitTransaction(wtxNew, reservekey))
        return _("SendMoneyWithInputTx(): The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");

    return "";
}

// scans nameindex.dat and return names with their last CNameIndex
bool CNameDB::ScanNames(
        const vector<unsigned char>& vchName,
        unsigned int nMax,
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
            CNameRecord val;
            ssValue >> val;
            if (val.deleted() || val.vtxPos.empty())
                continue;
            nameScan.push_back(make_pair(vchName, make_pair(val.vtxPos.back(), val.nExpiresAt)));
        }

        if (nameScan.size() >= nMax)
            break;
    }
    pcursor->close();
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
    //printf("IsNameFeeEnough(): pindexBlock->nHeight = %d, op = %s, nameSize = %lu, valueSize = %lu, nRentalDays = %d, txFee = %"PRI64d"\n",
    //       lastPoW->nHeight, nameFromOp(nti.op).c_str(), nti.vchName.size(), nti.vchValue.size(), nti.nRentalDays, txFee);

    bool txFeePass = false;
    for (int i = 1; i <= 10; i++)
    {
        int64 netFee = GetNameOpFee(lastPoW, nti.nRentalDays, nti.op, nti.vchName, nti.vchValue);
        //printf("                 : netFee = %"PRI64d", lastPoW->nHeight = %d\n", netFee, lastPoW->nHeight);
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
bool CNamecoinHooks::IsNameFeeEnough(CTxDB& txdb, const CTransaction &tx)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return false;

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
        return false;

    map<uint256, CTxIndex> unused;
    return ::IsNameFeeEnough(txdb, tx, nti, pindexBest, unused, false, false);
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
    CNameRecord nameRec;
    if (!dbName.ReadName(vchName, nameRec) || nameRec.vtxPos.empty())
        return false;
    CNameIndex& txPos = nameRec.vtxPos[nameRec.nLastActiveChainIndex];

    if (!tx.ReadFromDisk(txPos.txPos))
        return error("GetFirstTxOfName() : could not read tx from disk");
    return true;
}

bool GetLastTxOfName(CNameDB& dbName, const vector<unsigned char> &vchName, CTransaction& tx, CNameRecord &nameRec)
{
    if (!dbName.ReadName(vchName, nameRec))
        return false;
    if (nameRec.deleted() || nameRec.vtxPos.empty())
        return false;

    CNameIndex& txPos = nameRec.vtxPos.back();

    if (!tx.ReadFromDisk(txPos.txPos))
        return error("GetLastTxOfName() : could not read tx from disk");
    return true;
}

bool GetLastTxOfName(CNameDB& dbName, const vector<unsigned char> &vchName, CTransaction& tx)
{
    CNameRecord nameRec;
    return GetLastTxOfName(dbName, vchName, tx, nameRec);
}


Value sendtoname(const Array& params, bool fHelp)
{
    if (fHelp || params.size() < 2 || params.size() > 4)
        throw runtime_error(
            "sendtoname <name> <amount> [comment] [comment-to]\n"
            "<amount> is a real and is rounded to the nearest 0.01"
            + HelpRequiringPassphrase());

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

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

    return ::IsMine(*pwalletMain, scriptPubKey);
}

Value name_list(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 1)
        throw runtime_error(
                "name_list [<name>]\n"
                "list my own names"
                );

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

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

        if (mapNames.count(ntiWalllet.vchName)) // already added info about this name
            continue;

        CTransaction tx;
        CNameRecord nameRec;
        if (!GetLastTxOfName(dbName, ntiWalllet.vchName, tx, nameRec))
            continue;

        NameTxInfo nti;
        if (!DecodeNameTx(tx, nti, false, true))
            continue;

        if (vchNameUniq.size() > 0 && vchNameUniq != nti.vchName)
            continue;

        if (!dbName.ExistsName(nti.vchName))
            continue;

        nti.nExpiresAt = nameRec.nExpiresAt;
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
    if (fHelp || params.size() < 1 || params.size() > 2)
        throw runtime_error(
            "name_show <name> [filepath]\n"
            "Show values of a name.\n"
            "If filepath is specified name value will be saved in that file in binary format (file will be overwritten!).\n"
            );

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

    Object oName;
    vector<unsigned char> vchName = vchFromValue(params[0]);
    string name = stringFromVch(vchName);
    NameTxInfo nti;
    {
        LOCK(cs_main);
        CNameRecord nameRec;
        CNameDB dbName("r");
        if (!dbName.ReadName(vchName, nameRec))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from name DB");

        if (nameRec.vtxPos.size() < 1)
            throw JSONRPCError(RPC_WALLET_ERROR, "no result returned");

        CTransaction tx;
        if (!tx.ReadFromDisk(nameRec.vtxPos.back().txPos))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to read from from disk");

        if (!DecodeNameTx(tx, nti, false, true))
            throw JSONRPCError(RPC_WALLET_ERROR, "failed to decode name");

        oName.push_back(Pair("name", name));
        string value = stringFromVch(nti.vchValue);
        oName.push_back(Pair("value", value));
        oName.push_back(Pair("txid", tx.GetHash().GetHex()));
        oName.push_back(Pair("address", nti.strAddress));
        oName.push_back(Pair("expires_in", nameRec.nExpiresAt - pindexBest->nHeight));
        oName.push_back(Pair("expires_at", nameRec.nExpiresAt));
        oName.push_back(Pair("time", (boost::int64_t)tx.nTime));
        if (nameRec.deleted())
            oName.push_back(Pair("deleted", true));
        else
            if (nameRec.nExpiresAt - pindexBest->nHeight <= 0)
                oName.push_back(Pair("expired", true));
    }

    if (params.size() > 1)
    {
        string filepath = params[1].get_str();
        ofstream file;
        file.open(filepath.c_str(), ios::out | ios::binary | ios::trunc);
        if (!file.is_open())
            throw JSONRPCError(RPC_PARSE_ERROR, "Failed to open file. Check if you have permission to open it.");

        file.write((const char*)&nti.vchValue[0], nti.vchValue.size());
        file.close();
    }

    return oName;
}

// used for sorting in name_filter by nHeight
bool mycompare2 (const Object &lhs, const Object &rhs)
{
    int pos = 2; //this should exactly match field name position in name_filter

    return lhs[pos].value_.get_int() < rhs[pos].value_.get_int();
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

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

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
    vector<Object> oRes;

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

        CNameRecord nameRec;
        if (!dbName.ReadName(pairScan.first, nameRec))
            continue;

        // max age
        int nHeight = nameRec.vtxPos[nameRec.nLastActiveChainIndex].nHeight;
        if(nMaxAge != 0 && pindexBest->nHeight - nHeight >= nMaxAge)
            continue;

        // from limits
        nCountFrom++;
        if(nCountFrom < nFrom + 1)
            continue;

        Object oName;
        if (!fStat) {
            oName.push_back(Pair("name", name));

            string value = stringFromVch(txName.vchValue);
            oName.push_back(Pair("value", limitString(value, 300, "\n...(value too large - use name_show to see full value)")));

            oName.push_back(Pair("registered_at", nHeight)); // pos = 2 in comparison function (above name_filter)

            int nExpiresIn = nameRec.nExpiresAt - pindexBest->nHeight;
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

    Array oRes2;
    if (!fStat)
    {
        std::sort(oRes.begin(), oRes.end(), mycompare2); //sort by nHeight
        BOOST_FOREACH(const Object& res, oRes)
            oRes2.push_back(res);
    }
    else
    {
        Object oStat;
        oStat.push_back(Pair("blocks",    (int)nBestHeight));
        oStat.push_back(Pair("count",     (int)oRes2.size()));
        //oStat.push_back(Pair("sha256sum", SHA256(oRes), true));
        return oStat;
    }

    return oRes2;
}

Value name_scan(const Array& params, bool fHelp)
{
    if (fHelp || params.size() > 3)
        throw runtime_error(
                "name_scan [start-name] [max-returned] [max-value-length=-1]\n"
                "Scan all names, starting at start-name and returning a maximum number of entries (default 500)\n"
                "You can also control the length of shown value (-1 = full value)\n"
                );

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

    vector<unsigned char> vchName;
    int nMax = 500;
    int mMaxShownValue = -1;
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

    if (params.size() > 2)
    {
        Value vMax = params[2];
        ConvertTo<double>(vMax);
        mMaxShownValue = (int)vMax.get_real();
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
        vector<unsigned char> vchValue = txName.vchValue;

        string value = stringFromVch(vchValue);
        oName.push_back(Pair("value", limitString(value, mMaxShownValue, "\n...(value too large - use name_show to see full value)")));
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
        unsigned int nChunks = ceil(vchValue.size() / 520.0);

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

bool IsWalletLocked(NameTxReturn& ret)
{
    if (pwalletMain->IsLocked())
    {
        ret.err_code = RPC_WALLET_UNLOCK_NEEDED;
        ret.err_msg = "Error: Please enter the wallet passphrase with walletpassphrase first.";
        return true;
    }
    if (fWalletUnlockMintOnly)
    {
        ret.err_code = RPC_WALLET_UNLOCK_NEEDED;
        ret.err_msg = "Error: Wallet unlocked for block minting only, unable to create transaction.";
        return true;
    }
    return false;
}

Value name_new(const Array& params, bool fHelp)
{
    if (fHelp || params.size() != 3)
        throw runtime_error(
                "name_new <name> <value> <days>\n"
                "Creates new key->value pair which expires after specified number of days.\n"
                "Cost is square root of (1% of last PoW + 1% per year of last PoW)."
                + HelpRequiringPassphrase());

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

    vector<unsigned char> vchName = vchFromValue(params[0]);
    vector<unsigned char> vchValue = vchFromValue(params[1]);
    int nRentalDays = params[2].get_int();
    //printf("name_new(): vchValue.size = %lu\n", (unsigned long)vchValue.size());

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

    if (IsWalletLocked(ret))
        return ret;

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

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

    vector<unsigned char> vchName = vchFromValue(params[0]);
    vector<unsigned char> vchValue = vchFromValue(params[1]);
    int nRentalDays = params[2].get_int();
    string strAddress = "";
    if (params.size() == 4)
        strAddress = params[3].get_str();
    //printf("name_update(): vchValue.size = %lu\n", (unsigned long)vchValue.size());

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

    if (IsWalletLocked(ret))
        return ret;

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
                ret.err_msg = "FirstBitcoinCapitalCorp address is invalid";
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

        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];

        int64 prevFee = nTransactionFee;
        nTransactionFee = GetNameOpFee(pindexBest, nRentalDays, OP_NAME_UPDATE, vchName, vchValue);
        string strError = SendMoneyWithInputTx(nameScript, CENT, 0, wtxIn, wtx);
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

    if (!IsSynchronized())
        throw runtime_error("Blockchain is still downloading - wait until it is done.");

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

    if (IsWalletLocked(ret))
        return ret;

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

        CWalletTx& wtxIn = pwalletMain->mapWallet[wtxInHash];

        string strError = SendMoneyWithInputTx(nameScript, CENT, 0, wtxIn, wtx);

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

void createNameIndexFile()
{
    printf("Scanning blockchain for names to create fast index...\n");

    // create empty nameindex.dat
    {
        CNameDB dbName("cr+");
    }

    // scan blockchain to fill nameindex.dat
    CTxDB txdb("r");
    CBlockIndex* pindex = pindexGenesisBlock;
    {
        LOCK(cs_main);
        while (pindex)
        {
            hooks->ConnectBlock(txdb, pindex);
            pindex = pindex->pnext;
        }
    }
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
    for (unsigned int i = 0; i < tx.vout.size(); i++)
    {
        const CTxOut& out = tx.vout[i];
        NameTxInfo ntiTmp;
        if (DecodeNameScript(out.scriptPubKey, ntiTmp, checkValuesCorrectness, checkAddressAndIfIsMine))
        {
            // If more than one name op, fail
            if (found)
                return false;

            nti = ntiTmp;
            nti.nOut = i;
            found = true;
        }
    }

    if (found) nti.err_msg = "";
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
        error("AddToPendingNames() : no output in tx %s\n", tx.ToString().c_str());
        return;
    }

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
    {
        error("AddToPendingNames() : could not decode name script in tx %s", tx.ToString().c_str());
        return;
    }

    {
        LOCK(cs_main);
        mapNamePending[nti.vchName].insert(tx.GetHash());
        printf("AddToPendingNames(): added %s %s from tx %s", nameFromOp(nti.op).c_str(), stringFromVch(nti.vchName).c_str(), tx.ToString().c_str());
    }
}

// Checks name tx and save name data to vName if valid
// returns true if: (tx is valid name tx) OR (tx is not a name tx)
// returns false if tx is invalid name tx
bool ConnectInputs(CTxDB& txdb,
        map<uint256, CTxIndex>& mapTestPool,
        const CTransaction& tx,
        vector<CTransaction>& vTxPrev, //vector of all input transactions
        vector<CTxIndex>& vTxindex,
        const CBlockIndex* pindexBlock,
        const CDiskTxPos& txPos,
        vector<nameTempProxy>& vName)
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
                return error("ConnectInputsHook() : multiple previous name transactions in %s", tx.GetHash().GetHex().c_str());
            found = true;
            nInput = i;
        }
    }

//read name tx
    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
    {
        if (pindexBlock->nHeight > RELEASE_HEIGHT)
            return error("ConnectInputsHook(): could not decode namecoin tx %s in block %d", tx.GetHash().GetHex().c_str(), pindexBlock->nHeight);
        return false;
    }

    vector<unsigned char> vchName = nti.vchName;
    string sName = stringFromVch(vchName);

    string info = "ConnectInputsHook(): name=" + sName + ", value=" + stringFromVch(nti.vchValue) + ", tx=" + tx.GetHash().GetHex() +
        ", block=" + boost::lexical_cast<string>(pindexBlock->nHeight) + " -";

    CNameDB dbName("r");

    switch (nti.op)
    {
        case OP_NAME_NEW:
        {
            //scan last 10 PoW block for tx fee that matches the one specified in tx
            if (!IsNameFeeEnough(txdb, tx, nti, pindexBlock, mapTestPool, true, false))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("%s rejected name_new because not enough fee", info.c_str());
                return false;
            }

            if (NameActive(dbName, vchName, pindexBlock->nHeight))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("%s name_new on an unexpired name", info.c_str());
                return false;
            }
            break;
        }
        case OP_NAME_UPDATE:
        {
            //scan last 10 PoW block for tx fee that matches the one specified in tx
            if (!IsNameFeeEnough(txdb, tx, nti, pindexBlock, mapTestPool, true, false))
            {
                if (pindexBlock->nHeight > RELEASE_HEIGHT)
                    return error("%s rejected name_update because not enough fee", info.c_str());
                return false;
            }

            if (!found || (prev_nti.op != OP_NAME_NEW && prev_nti.op != OP_NAME_UPDATE))
                return error("%s name_update without previous new or update tx", info.c_str());

            if (prev_nti.vchName != vchName)
                return error("%s name_update name mismatch", info.c_str());

            if (!NameActive(dbName, vchName, pindexBlock->nHeight))
                return error("%s name_update on an expired name", info.c_str());
            break;
        }
        case OP_NAME_DELETE:
        {
            if (!found || (prev_nti.op != OP_NAME_NEW && prev_nti.op != OP_NAME_UPDATE))
                return error("%s name_delete without previous new or update tx", info.c_str());

            if (prev_nti.vchName != vchName)
                return error("%s name_delete name mismatch", info.c_str());

            if (!NameActive(dbName, vchName, pindexBlock->nHeight))
                return error("%s name_delete on expired name", info.c_str());
            break;
        }
        default:
            return error("%s unknown name operation", info.c_str());
    }

    CNameRecord nameRec;
    if (dbName.ExistsName(vchName) && !dbName.ReadName(vchName, nameRec))
        return error("ConnectInputsHook() : failed to read from name DB for name %s in tx %s", sName.c_str(), tx.GetHash().GetHex().c_str());

    if ((nti.op == OP_NAME_UPDATE || nti.op == OP_NAME_DELETE) && !CheckNameTxPos(nameRec.vtxPos, vTxindex[nInput].pos))
    {
        if (pindexBlock->nHeight > RELEASE_HEIGHT)
            return error("ConnectInputsHook() : name %s in tx %s rejected, since previous tx (%s) is not in the name DB\n", sName.c_str(), tx.GetHash().ToString().c_str(), vTxPrev[nInput].GetHash().ToString().c_str());
        return false;
    }

    // all checks passed - record tx information to vName. It will be sorted by nTime and writen to nameindex.dat at the end of ConnectBlock
    CNameIndex txPos2;
    txPos2.nHeight = pindexBlock->nHeight;
    txPos2.vchValue = nti.vchValue;
    txPos2.txPos = txPos;

    nameTempProxy tmp;
    tmp.nTime = tx.nTime;
    tmp.vchName = vchName;
    tmp.op = nti.op;
    tmp.hash = tx.GetHash();
    tmp.ind = txPos2;

    vName.push_back(tmp);
    return true;
}

bool CNamecoinHooks::DisconnectInputs(const CTransaction& tx)
{
    if (tx.nVersion != NAMECOIN_TX_VERSION)
        return true;

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti))
        return error("DisconnectInputsHook() : could not decode namecoin tx");

    {
        CNameDB dbName("cr+");
        dbName.TxnBegin();

        CNameRecord nameRec;
        if (!dbName.ReadName(nti.vchName, nameRec))
            return error("DisconnectInputsHook() : failed to read from name DB");

        // vtxPos might be empty if we pruned expired transactions.  However, it should normally still not
        // be empty, since a reorg cannot go that far back.  Be safe anyway and do not try to pop if empty.
        if (nameRec.vtxPos.size() > 0)
        {
            // check if tx matches last tx in nameindex.dat
            CTransaction lastTx;
            lastTx.ReadFromDisk(nameRec.vtxPos.back().txPos);
            assert(lastTx.GetHash() == tx.GetHash());

            // remove tx
            nameRec.vtxPos.pop_back();

            if (nameRec.vtxPos.size() == 0) // delete empty record
                return dbName.EraseName(nti.vchName);

            // if we have deleted name_new - recalculate Last Active Chain Index
            if (nti.op == OP_NAME_NEW)
                for (int i = nameRec.vtxPos.size() - 1; i >= 0; i--)
                    if (nameRec.vtxPos[i].op == OP_NAME_NEW)
                    {
                        nameRec.nLastActiveChainIndex = i;
                        break;
                    }
        }
        else
            return dbName.EraseName(nti.vchName); // delete empty record

        if (!CalculateExpiresAt(nameRec))
            return error("DisconnectInputsHook() : failed to calculate expiration time before writing to name DB");
        if (!dbName.WriteName(nti.vchName, nameRec))
            return error("DisconnectInputsHook() : failed to write to name DB");

        dbName.TxnCommit();
    }

    return true;
}

string nameFromOp(int op)
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

// Executes name operations in vName and writes result to nameindex.dat.
// NOTE: the block should already be written to blockchain by now - otherwise this may fail.
bool CNamecoinHooks::ConnectBlock(CTxDB& txdb, CBlockIndex* pindex)
{
    CBlock block;
    block.ReadFromDisk(pindex, true);

    // read name txs and add them to vName if they pass all checks.
    CTxIndex txindex;
    // NOTE: all tx in block have been validated by upper function, so it is safe to iterate over them
    vector<nameTempProxy> vName;
    BOOST_FOREACH(CTransaction& tx, block.vtx)
    {
        if (tx.nVersion != NAMECOIN_TX_VERSION)
            continue;

        if(!txdb.ReadTxIndex(tx.GetHash(), txindex))
            return error("ConnectBlockHook() : failed to read tx from disk, aborting.");

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

        if (!ConnectInputs(txdb, mapTestPool, tx, vTxPrev, vTxindex, pindex, txindex.pos, vName))
        {
            // remove tx from mapNamePending, wallet and mempool
            NameTxInfo nti;
            if (DecodeNameTx(tx, nti, false))
            {
                std::map<std::vector<unsigned char>, std::set<uint256> >::iterator mi = mapNamePending.find(nti.vchName);
                if (mi != mapNamePending.end())
                    mi->second.erase(tx.GetHash());
                if (mi->second.empty())
                    mapNamePending.erase(nti.vchName);
            }

            LOCK2(cs_main, pwalletMain->cs_wallet);
            pwalletMain->EraseFromWallet(tx.GetHash());
            mempool.remove(tx);
        }
    }

    if (vName.empty())
        return true;

    // All of these name ops should succed. If there is an error - nameindex.dat is probably corrupt.
    CNameDB dbName("cr+");
    set< vector<unsigned char> > sNameNew;
    BOOST_FOREACH(const nameTempProxy &i, vName)
    {
        string info = "ConnectBlock(): trying to write " + nameFromOp(i.op) + " " + stringFromVch(i.vchName) +
            " in block " + boost::lexical_cast<string>(pindex->nHeight) + " to nameindex.dat...";

        CNameRecord nameRec;
        if (dbName.ExistsName(i.vchName) && !dbName.ReadName(i.vchName, nameRec))
            return error("%s failed to read from name DB", info.c_str());

        dbName.TxnBegin();

        // only first name_new for same name in same block will get written
        if  (i.op == OP_NAME_NEW && sNameNew.count(i.vchName))
            continue;

        nameRec.vtxPos.push_back(i.ind); // add

        // if starting new chain - save position of where it starts
        if (i.op == OP_NAME_NEW)
            nameRec.nLastActiveChainIndex = nameRec.vtxPos.size()-1;

        // limit to 100 tx per name or a full single chain - whichever is larger
        if (nameRec.vtxPos.size() > NAMEINDEX_CHAIN_SIZE
             && nameRec.vtxPos.size() - nameRec.nLastActiveChainIndex + 1 <= NAMEINDEX_CHAIN_SIZE)
        {
            int d = nameRec.vtxPos.size() - NAMEINDEX_CHAIN_SIZE; // number of elements to delete
            nameRec.vtxPos.erase(nameRec.vtxPos.begin(), nameRec.vtxPos.begin() + d);
            nameRec.nLastActiveChainIndex -= d; // move last index backwards by d elements
            assert(nameRec.nLastActiveChainIndex >= 0);
        }

        // save name op
        nameRec.vtxPos.back().op = i.op;

        if (!CalculateExpiresAt(nameRec))
            return error("%s failed to calculate expiration time", info.c_str());
        if (!dbName.WriteName(i.vchName, nameRec))
            return error("%s failed on write", info.c_str());
        if  (i.op == OP_NAME_NEW)
            sNameNew.insert(i.vchName);

        {
            // remove from pending names list
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
            return error("%s failed on write", info.c_str());
        printf("%s success!\n", info.c_str());
    }

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

bool GetPendingNameValue(const vector<unsigned char> &vchName, vector<unsigned char> &vchValue)
{
    if (!mapNamePending.count(vchName))
        return false;
    if (mapNamePending[vchName].empty())
        return false;

    // if there is a set of pending op on a single name - select last one, by nTime
    CTransaction tx;
    tx.nTime = 0;
    bool found = false;
    BOOST_FOREACH(uint256 hash, mapNamePending[vchName])
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
        return false;

    NameTxInfo nti;
    if (!DecodeNameTx(tx, nti, false, true))
        return false;

    vchValue = nti.vchValue;
    return true;
}

// if pending is true it will grab value from pending names. If there are no pending names it will grab value from nameindex.dat
bool GetNameValue(const vector<unsigned char> &vchName, vector<unsigned char> &vchValue, bool checkPending)
{
    bool found = false;
    if (checkPending)
        found = GetPendingNameValue(vchName, vchValue);

    if (found)
        return true;
    else
    {
        CNameDB dbName("r");
        CNameRecord nameRec;

        if (!NameActive(vchName))
            return false;
        if (!dbName.ReadName(vchName, nameRec))
            return false;
        if (nameRec.vtxPos.empty())
            return false;

        vchValue = nameRec.vtxPos.back().vchValue;
        return true;
    }
}

bool CNamecoinHooks::DumpToTextFile()
{
    CNameDB dbName("r");
    return dbName.DumpToTextFile();
}


bool CNameDB::DumpToTextFile()
{
    ofstream myfile ("example111.txt");
    if (!myfile.is_open())
        return false;

    Dbc* pcursor = GetCursor();
    if (!pcursor)
        return false;


    vector<unsigned char> vchName;
    map<string, CNameRecord> mapNames;
    unsigned int fFlags = DB_SET_RANGE;
    while (true)
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
            CNameRecord val;
            ssValue >> val;
            if (val.vtxPos.empty())
                continue;
            mapNames[stringFromVch(vchName)] = val;
        }
    }

    BOOST_FOREACH(PAIRTYPE(const string, CNameRecord)& item, mapNames)
    {
        myfile << "name = " << item.first << "\n";
        myfile << "nExpiresAt " << item.second.nExpiresAt << "\n";
        myfile << "nLastActiveChainIndex " << item.second.nLastActiveChainIndex << "\n";
        myfile << "vtxPos:\n";
        for (unsigned int i = 0; i < item.second.vtxPos.size(); i++)
        {
            myfile << "    nHeight = " << item.second.vtxPos[i].nHeight << " op = " << item.second.vtxPos[i].op << "\n";
            myfile << "    value = " << stringFromVch(item.second.vtxPos[i].vchValue) << "\n";
        }
        myfile << "\n\n";
        myfile.flush();
    }

    pcursor->close();
    myfile.close();
    return true;
}
