#include "nametablemodel.h"

#include "guiutil.h"
#include "walletmodel.h"
#include "guiconstants.h"

#include <QTimer>

#include "wallet.h"

// ExpiresIn column is right-aligned as it contains numbers
static int column_alignments[] = {
        Qt::AlignLeft|Qt::AlignVCenter,     // Name
        Qt::AlignLeft|Qt::AlignVCenter,     // Value
        Qt::AlignLeft|Qt::AlignVCenter,     // Address
        Qt::AlignRight|Qt::AlignVCenter     // Expires in
    };

struct NameTableEntryLessThan
{
    bool operator()(const NameTableEntry &a, const NameTableEntry &b) const
    {
        return a.name < b.name;
    }
    bool operator()(const NameTableEntry &a, const QString &b) const
    {
        return a.name < b;
    }
    bool operator()(const QString &a, const NameTableEntry &b) const
    {
        return a < b.name;
    }
};

// Private implementation
class NameTablePriv
{
public:
    CWallet *wallet;
    QList<NameTableEntry> cachedNameTable;
    NameTableModel *parent;

    NameTablePriv(CWallet *wallet, NameTableModel *parent):
        wallet(wallet), parent(parent) {}

    void refreshNameTable()
    {
        cachedNameTable.clear();

        map<vector<unsigned char>, NameTxInfo> scannedNames = GetNameList(); //this excludes pending name ops

        BOOST_FOREACH(const PAIRTYPE(vector<unsigned char>, NameTxInfo)& item, scannedNames)
        {
            // TODO check if there is pending name ops.
            if (mapNamePending.count(item.second.vchName) && mapNamePending[item.second.vchName].size())
            {
                uint256 hash = *(mapNamePending[item.second.vchName].begin());
                if (!mempool.exists(hash))
                    continue;
                CTransaction tx = mempool.mapTx[hash];
                NameTxInfo nti;
                if(!DecodeNameTx(tx, nti, false, true))
                    continue;

                int nHeightStatus;
                if (nti.op == OP_NAME_NEW)
                    nHeightStatus = NameTableEntry::NAME_NEW;
                else if (nti.op == OP_NAME_UPDATE)
                    nHeightStatus = NameTableEntry::NAME_UPDATE;
                else if (nti.op == OP_NAME_UPDATE)
                    nHeightStatus = NameTableEntry::NAME_DELETE;
                NameTableEntry nte(stringFromVch(item.second.vchName), stringFromVch(nti.vchValue), nti.strAddress, nHeightStatus, nti.nIsMine);
                cachedNameTable.append(nte);
            }
            else
            {
                int nTotalLifeTime, nNameHeight;
                if (!GetExpirationData(item.second.vchName, nTotalLifeTime, nNameHeight))
                    continue;

                NameTableEntry nte(stringFromVch(item.second.vchName), stringFromVch(item.second.vchValue), item.second.strAddress, nTotalLifeTime + nNameHeight, item.second.nIsMine);
                cachedNameTable.append(nte);
            }
        }

        // qLowerBound() and qUpperBound() require our cachedNameTable list to be sorted in asc order
        qSort(cachedNameTable.begin(), cachedNameTable.end(), NameTableEntryLessThan());
    }

    void updateEntry(const NameTableEntry &nameObj, int status, int *outNewRowIndex = NULL)
    {
        updateEntry(nameObj.name, nameObj.value, nameObj.address, nameObj.nExpiresAt, status, outNewRowIndex);
    }

    void updateEntry(const QString &name, const QString &value, const QString &address, int nExpiresAt, int status, int *outNewRowIndex = NULL)
    {
        // Find name in model
        QList<NameTableEntry>::iterator lower = qLowerBound(
            cachedNameTable.begin(), cachedNameTable.end(), name, NameTableEntryLessThan());
        QList<NameTableEntry>::iterator upper = qUpperBound(
            cachedNameTable.begin(), cachedNameTable.end(), name, NameTableEntryLessThan());
        int lowerIndex = (lower - cachedNameTable.begin());
        int upperIndex = (upper - cachedNameTable.begin());
        bool inModel = (lower != upper);

        switch(status)
        {
        case CT_NEW:
            if (inModel)
            {
                if (outNewRowIndex)
                {
                    *outNewRowIndex = parent->index(lowerIndex, 0).row();
                    // HACK: ManageNamesPage uses this to ensure updating and get selected row,
                    // so we do not write warning into the log in this case
                }
                else
                    OutputDebugStringF("Warning: NameTablePriv::updateEntry: Got CT_NEW, but entry is already in model\n");
                break;
            }
            parent->beginInsertRows(QModelIndex(), lowerIndex, lowerIndex);
            cachedNameTable.insert(lowerIndex, NameTableEntry(name, value, address, nExpiresAt));
            parent->endInsertRows();
            if (outNewRowIndex)
                *outNewRowIndex = parent->index(lowerIndex, 0).row();
            break;
        case CT_UPDATED:
            if (!inModel)
            {
                OutputDebugStringF("Warning: NameTablePriv::updateEntry: Got CT_UPDATED, but entry is not in model\n");
                break;
            }
            lower->name = name;
            lower->value = value;
            lower->address = address;
            lower->nExpiresAt = nExpiresAt;
            parent->emitDataChanged(lowerIndex);
            break;
        case CT_DELETED:
            if (!inModel)
            {
                OutputDebugStringF("Warning: NameTablePriv::updateEntry: Got CT_DELETED, but entry is not in model\n");
                break;
            }
            parent->beginRemoveRows(QModelIndex(), lowerIndex, upperIndex-1);
            cachedNameTable.erase(lower, upper);
            parent->endRemoveRows();
            break;
        }
    }

    int size()
    {
        return cachedNameTable.size();
    }

    NameTableEntry *index(int idx)
    {
        if (idx >= 0 && idx < cachedNameTable.size())
        {
            return &cachedNameTable[idx];
        }
        else
        {
            return NULL;
        }
    }
};


NameTableModel::NameTableModel(CWallet *wallet, WalletModel *parent) :
    QAbstractTableModel(parent), walletModel(parent), wallet(wallet), priv(0), cachedNumBlocks(0)
{
    columns << tr("Name") << tr("Value") << tr("Address") << tr("Expires in");
    priv = new NameTablePriv(wallet, this);
    priv->refreshNameTable();

    QTimer *timer = new QTimer(this);
    connect(timer, SIGNAL(timeout()), this, SLOT(update()));
    timer->start(MODEL_UPDATE_DELAY);
}

NameTableModel::~NameTableModel()
{
    delete priv;
}

void NameTableModel::update()
{
    if (nBestHeight != cachedNumBlocks)
    {
        LOCK(cs_main);

        cachedNumBlocks = nBestHeight;
        // Blocks came in since last poll.
        // Delete expired names and update status of pending name ops.
        for (int i = 0, n = priv->size(); i < n; i++)
        {
            NameTableEntry *item = priv->index(i);
            if (!item->HeightValid())
            {
                string strName = item->name.toStdString();
                vector<unsigned char> vchName(strName.begin(), strName.end());
                if (mapNamePending.count(vchName) && mapNamePending[vchName].size())
                    continue;
                else
                {
                    int nTotalLifeTime, nNameHeight;
                    if (!GetExpirationData(vchName, nTotalLifeTime, nNameHeight))
                        continue;
                    if (item->nExpiresAt == NameTableEntry::NAME_DELETE)
                        priv->updateEntry(item->name, item->value, item->address, nTotalLifeTime + nNameHeight, CT_DELETED);
                    else
                        priv->updateEntry(item->name, item->value, item->address, nTotalLifeTime + nNameHeight, CT_UPDATED);
                }
            }

            if (item->nExpiresAt - pindexBest->nHeight <= 0)
            {
                priv->updateEntry(item->name, item->value, item->address, item->nExpiresAt, CT_DELETED);
                // Data array changed - restart scan
                n = priv->size();
                i = -1;
            }
        }
        // Invalidate expiration counter for all rows.
        // Qt is smart enough to only actually request the data for the
        // visible rows.
        emit dataChanged(index(0, ExpiresIn), index(priv->size()-1, ExpiresIn));

        // add new name tx, if any
        BOOST_FOREACH(uint256 hash, wallet->vCheckNewNames)
        {
            CTransaction tx;
            uint256 hashBlock = 0;
            if (!GetTransaction(hash, tx, hashBlock))
                continue;
            NameTxInfo nti;
            if (!DecodeNameTx(tx, nti, false, true))
                continue;

            int nHeightStatus;
            if (nti.op == OP_NAME_NEW)
                nHeightStatus = NameTableEntry::NAME_NEW;
            else if (nti.op == OP_NAME_UPDATE)
                nHeightStatus = NameTableEntry::NAME_UPDATE;
            else if (nti.op == OP_NAME_UPDATE)
                nHeightStatus = NameTableEntry::NAME_DELETE;

            priv->updateEntry(QString::fromStdString(stringFromVch(nti.vchName)),
                              QString::fromStdString(stringFromVch(nti.vchValue)),
                              QString::fromStdString(nti.strAddress),
                              nHeightStatus,
                              CT_NEW);
        }
        wallet->vCheckNewNames.clear();
    }
}

int NameTableModel::rowCount(const QModelIndex &parent /* = QModelIndex()*/) const
{
    Q_UNUSED(parent);
    return priv->size();
}

int NameTableModel::columnCount(const QModelIndex &parent /* = QModelIndex()*/) const
{
    Q_UNUSED(parent);
    return columns.length();
}

QVariant NameTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid())
        return QVariant();

    NameTableEntry *rec = static_cast<NameTableEntry*>(index.internalPointer());

    if (role == Qt::DisplayRole || role == Qt::EditRole)
    {
        switch (index.column())
        {
        case Name:
            return rec->name;
        case Value:
            return rec->value;
        case Address:
            return rec->address;
        case ExpiresIn:
            if (!rec->HeightValid())
            {
                if (rec->nExpiresAt == NameTableEntry::NAME_NEW)
                    return QString("pending (new)");
                if (rec->nExpiresAt == NameTableEntry::NAME_UPDATE)
                    return QString("pending (update)");
                if (rec->nExpiresAt == NameTableEntry::NAME_DELETE)
                    return QString("pending (delete)");
            }
            else
            {
                return rec->nExpiresAt - pindexBest->nHeight;
            }
        }
    }
    else if (role == Qt::TextAlignmentRole)
        return column_alignments[index.column()];
    else if (role == Qt::FontRole)
    {
        QFont font;
        if (index.column() == Address)
            font = GUIUtil::bitcoinAddressFont();
        return font;
    }

    return QVariant();
}

QVariant NameTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (orientation == Qt::Horizontal)
    {
        if (role == Qt::DisplayRole)
        {
            return columns[section];
        }
        else if (role == Qt::TextAlignmentRole)
        {
            return column_alignments[section];
        }
        else if (role == Qt::ToolTipRole)
        {
            switch (section)
            {
            case Name:
                return tr("Name registered using Namecoin.");
            case Value:
                return tr("Data associated with the name.");
            case Address:
                return tr("Namecoin address to which the name is registered.");
            case ExpiresIn:
                return tr("Number of blocks, after which the name will expire. Update name to renew it.");
            }
        }
    }
    return QVariant();
}

Qt::ItemFlags NameTableModel::flags(const QModelIndex &index) const
{
    if (!index.isValid())
        return 0;
    //NameTableEntry *rec = static_cast<NameTableEntry*>(index.internalPointer());

    return Qt::ItemIsSelectable | Qt::ItemIsEnabled;
}

QModelIndex NameTableModel::index(int row, int column, const QModelIndex &parent /* = QModelIndex()*/) const
{
    Q_UNUSED(parent);
    NameTableEntry *data = priv->index(row);
    if (data)
    {
        return createIndex(row, column, priv->index(row));
    }
    else
    {
        return QModelIndex();
    }
}

void NameTableModel::updateEntry(const QString &name, const QString &value, const QString &address, int nHeight, int status, int *outNewRowIndex /* = NULL*/)
{
    priv->updateEntry(name, value, address, nHeight, status, outNewRowIndex);
}

void NameTableModel::emitDataChanged(int idx)
{
    emit dataChanged(index(idx, 0), index(idx, columns.length()-1));
}
