#include "walletmodel.h"
#include "guiconstants.h"
#include "optionsmodel.h"
#include "addresstablemodel.h"
#include "transactiontablemodel.h"

#include "ui_interface.h"
#include "wallet.h"
#include "walletdb.h" // for BackupWallet
#include "base58.h"
#include "namecoin.h"
#include "nametablemodel.h"

#include <QSet>

WalletModel::WalletModel(CWallet *wallet, OptionsModel *optionsModel, QObject *parent) :
    QObject(parent), wallet(wallet), optionsModel(optionsModel), addressTableModel(0),
    transactionTableModel(0),
    cachedBalance(0), cachedUnconfirmedBalance(0), cachedNumTransactions(0),
    cachedEncryptionStatus(Unencrypted)
{
    addressTableModel = new AddressTableModel(wallet, this);
    nameTableModel = new NameTableModel(wallet, this);
    transactionTableModel = new TransactionTableModel(wallet, this);
}

qint64 WalletModel::getBalance() const
{
    return wallet->GetBalance();
}

qint64 WalletModel::getStake() const
{
    return wallet->GetStake();
}

qint64 WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

int WalletModel::getNumTransactions() const
{
    int numTransactions = 0;
    {
        LOCK(wallet->cs_wallet);
        numTransactions = wallet->mapWallet.size();
    }
    return numTransactions;
}

void WalletModel::update()
{
    qint64 newBalance = getBalance();
    qint64 newUnconfirmedBalance = getUnconfirmedBalance();
    int newNumTransactions = getNumTransactions();
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedBalance != newBalance || cachedUnconfirmedBalance != newUnconfirmedBalance)
        emit balanceChanged(newBalance, getStake(), newUnconfirmedBalance);

    if(cachedNumTransactions != newNumTransactions)
        emit numTransactionsChanged(newNumTransactions);

    if(cachedEncryptionStatus != newEncryptionStatus)
        emit encryptionStatusChanged(newEncryptionStatus);

    cachedBalance = newBalance;
    cachedUnconfirmedBalance = newUnconfirmedBalance;
    cachedNumTransactions = newNumTransactions;
}

void WalletModel::updateAddressList()
{
    addressTableModel->update();
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

WalletModel::SendCoinsReturn WalletModel::sendCoins(const QList<SendCoinsRecipient> &recipients)
{
    qint64 total = 0;
    QSet<QString> setAddress;
    QString hex;

    if(recipients.empty())
    {
        return OK;
    }

    // Pre-check input data for validity
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        if(!validateAddress(rcp.address))
        {
            return InvalidAddress;
        }
        setAddress.insert(rcp.address);

        if(rcp.amount < MIN_TXOUT_AMOUNT)
        {
            return InvalidAmount;
        }
        total += rcp.amount;
    }

    if(recipients.size() > setAddress.size())
    {
        return DuplicateAddress;
    }

    if(total > getBalance())
    {
        return AmountExceedsBalance;
    }

    if((total + nTransactionFee) > getBalance())
    {
        return SendCoinsReturn(AmountWithFeeExceedsBalance, nTransactionFee);
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        // Sendmany
        std::vector<std::pair<CScript, int64> > vecSend;
        foreach(const SendCoinsRecipient &rcp, recipients)
        {
            CScript scriptPubKey;
            scriptPubKey.SetDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
            vecSend.push_back(make_pair(scriptPubKey, rcp.amount));
        }

        CWalletTx wtx;
        CReserveKey keyChange(wallet);
        int64 nFeeRequired = 0;
        bool fCreated = wallet->CreateTransaction(vecSend, wtx, keyChange, nFeeRequired);

        if(!fCreated)
        {
            if((total + nFeeRequired) > wallet->GetBalance())
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance, nFeeRequired);
            }
            return TransactionCreationFailed;
        }
        if(!ThreadSafeAskFee(nFeeRequired, tr("Sending...").toStdString()))
        {
            return Aborted;
        }
        if(!wallet->CommitTransaction(wtx, keyChange))
        {
            return TransactionCommitFailed;
        }
        hex = QString::fromStdString(wtx.GetHash().GetHex());
    }

    // Add addresses / update labels that we've sent to to the address book
    foreach(const SendCoinsRecipient &rcp, recipients)
    {
        std::string strAddress = rcp.address.toStdString();
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            std::map<CTxDestination, std::string>::iterator mi = wallet->mapAddressBook.find(dest);

            // Check if we have a new address or an updated label
            if (mi == wallet->mapAddressBook.end() || mi->second != strLabel)
            {
                wallet->SetAddressBookName(dest, strLabel);
            }
        }
    }

    return SendCoinsReturn(OK, 0, hex);
}

bool WalletModel::nameAvailable(const QString &name)
{
    std::string strName = name.toStdString();
    std::vector<unsigned char> vchName(strName.begin(), strName.end());

    std::vector<CNameIndex> vtxPos;
    CNameDB dbName("r");
    if (!dbName.ReadName(vchName, vtxPos))
        return true;

    if (vtxPos.size() < 1)
        return true;

    CDiskTxPos txPos = vtxPos[vtxPos.size() - 1].txPos;
    CTransaction tx;
    if (!tx.ReadFromDisk(txPos))
        return true;     // This may indicate error, rather than name availability

    std::vector<unsigned char> vchValue;
    int nHeight;
    uint256 hash;
    if (txPos.IsNull() || !GetValueOfTxPos(txPos, vchValue, hash, nHeight))
        return true;

    int nTotalLifeTime;
    if (!GetExpirationData(vchName, nTotalLifeTime, nHeight))
        return true;        // This also may indicate error, rather than name availability

    // TODO: should we subtract MIN_FIRSTUPDATE_DEPTH blocks? I think name_new may be possible when the previous registration is just about to expire
    if(nHeight + nTotalLifeTime - pindexBest->nHeight <= 0)
        return true;    // Expired

    return false;
}

WalletModel::NameNewReturn WalletModel::nameNew(const QString &name, const QString &value, int days)
{
    NameNewReturn ret;

    std::string strName = name.toStdString();
    ret.vchName = std::vector<unsigned char>(strName.begin(), strName.end());

    CWalletTx wtx;
    wtx.nVersion = NAMECOIN_TX_VERSION;

    uint64 rand = GetRand((uint64)-1);
    std::vector<unsigned char> vchRand = CBigNum(rand).getvch();
    std::vector<unsigned char> vchToHash(vchRand);
    vchToHash.insert(vchToHash.end(), ret.vchName.begin(), ret.vchName.end());
    uint160 hash = Hash160(vchToHash);

//    std::vector<unsigned char> vchPubKey = wallet->GetKeyFromKeyPool();
//    CScript scriptPubKeyOrig;
//    scriptPubKeyOrig.SetBitcoinAddress(vchPubKey);
//    ret.address = QString::fromStdString(scriptPubKeyOrig.GetBitcoinAddress());
//    CScript scriptPubKey;
//    scriptPubKey << OP_NAME_NEW << hash << OP_2DROP;
//    scriptPubKey += scriptPubKeyOrig;

//    CRITICAL_BLOCK(cs_main)
//    {
//        // Include additional fee to name_new, which will be re-used by name_firstupdate
//        // In this way we can preconfigure name_firstupdate

//        int64 nFirstUpdateFee = 0;
//        int64 nPrevFirstUpdateFee;
//        CReserveKey reservekey(wallet);

//        PreparedNameFirstUpdate prep;
//        prep.rand = rand;

//        // 1st pass: compute fee for name_firstupdate
//        // 2nd pass: try using that fee in name_new
//        for (int pass = 1; pass <= 2; pass++)
//        {
//            nPrevFirstUpdateFee = nFirstUpdateFee;
//            reservekey.ReturnKey();

//            // Prepare name_new, but do not commit until we prepare name_firstupdate
//            printf("name_new GUI: SendMoneyPrepare (pass %d)\n", pass);
//            std::string strError = wallet->SendMoneyPrepare(scriptPubKey, MIN_AMOUNT + nFirstUpdateFee, wtx, reservekey, pass == 1);
//            if (!strError.empty())
//            {
//                printf("name_new GUI error: %s\n", strError.c_str());
//                ret.ok = false;
//                ret.err_msg = QString::fromStdString(strError);
//                return ret;
//            }

//            ret.hex = wtx.GetHash();
//            ret.rand = rand;
//            ret.hash = hash;

//            // Prepare name_firstupdate (with empty value)
//            // FIXME: AddSupportingTransactions will fail and write msg to the log
//            // Though we manually call AddSupportingTransactions (near the end of this function)
//            printf("name_new GUI: nameFirstUpdateCreateTx (pass %d)\n", pass);
//            strError = nameFirstUpdateCreateTx(prep.wtx, ret.vchName, wtx, rand, prep.vchData, &nFirstUpdateFee);
//            if (!strError.empty())
//            {
//                printf("name_new GUI error: %s\n", strError.c_str());
//                ret.ok = false;
//                ret.err_msg = QString::fromStdString(strError);
//                return ret;
//            }
//            if (nPrevFirstUpdateFee == nFirstUpdateFee)
//                break;
//        }
//        if (nPrevFirstUpdateFee != nFirstUpdateFee)
//            printf("name_new GUI warning: cannot prepare fee for automatic name_firstupdate - fee changed from %s to %s\n", FormatMoney(nPrevFirstUpdateFee).c_str(), FormatMoney(nFirstUpdateFee).c_str());

//        printf("Automatic name_firstupdate created for name %s (initial, with empty value), created tx: %s:\n%s", qPrintable(name), prep.wtx.GetHash().GetHex().c_str(), prep.wtx.ToString().c_str());

//        // name_firstupdate prepared, let's commit name_new
//        if (!wallet->CommitTransaction(wtx, reservekey))
//        {
//            ret.ok = false;
//            ret.err_msg = tr("Error: The transaction was rejected.  This might happen if some of the coins in your wallet were already spent, such as if you used a copy of wallet.dat and coins were spent in the copy but not marked as spent here.");
//            return ret;
//        }

//        // name_new committed successfully, from this point we must return ok
//        ret.ok = true;

//        mapMyNames[ret.vchName] = ret.hex;
//        mapMyNameHashes[ret.hash] = ret.vchName;
//        mapMyNameFirstUpdate[ret.vchName] = prep;

//        {
//            CTxDB txdb("r");
//            CRITICAL_BLOCK(wallet->cs_wallet)
//            {
//                // Fill vtxPrev by copying from previous transactions vtxPrev
//                prep.wtx.AddSupportingTransactions(txdb);
//                wallet->WriteNameFirstUpdate(ret.vchName, ret.hex, rand, prep.vchData, prep.wtx);
//            }
//        }
//    }
    return ret;
}

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

NameTableModel *WalletModel::getNameTableModel()
{
    return nameTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return BackupWallet(*wallet, filename.toLocal8Bit().data());
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        emit requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *wallet, bool valid, bool relock):
        wallet(wallet),
        valid(valid),
        relock(relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}
