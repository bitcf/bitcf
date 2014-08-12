#include "managenamespage.h"
#include "ui_managenamespage.h"

#include "walletmodel.h"
#include "nametablemodel.h"
#include "csvmodelwriter.h"
#include "guiutil.h"
#include "../base58.h"
#include "../main.h"
//#include "../hook.h"
#include "../wallet.h"
#include "guiconstants.h"
#include "ui_interface.h"
//#include "configurenamedialog.h"

#include <QSortFilterProxyModel>
#include <QMessageBox>
#include <QMenu>
#include <QScrollBar>

//
// NameFilterProxyModel
//

NameFilterProxyModel::NameFilterProxyModel(QObject *parent /* = 0*/)
    : QSortFilterProxyModel(parent)
{
}

void NameFilterProxyModel::setNameSearch(const QString &search)
{
    nameSearch = search;
    invalidateFilter();
}

void NameFilterProxyModel::setValueSearch(const QString &search)
{
    valueSearch = search;
    invalidateFilter();
}

void NameFilterProxyModel::setAddressSearch(const QString &search)
{
    addressSearch = search;
    invalidateFilter();
}

bool NameFilterProxyModel::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);

    QString name = index.sibling(index.row(), NameTableModel::Name).data(Qt::EditRole).toString();
    QString value = index.sibling(index.row(), NameTableModel::Value).data(Qt::EditRole).toString();
    QString address = index.sibling(index.row(), NameTableModel::Address).data(Qt::EditRole).toString();

    Qt::CaseSensitivity case_sens = filterCaseSensitivity();
    return name.contains(nameSearch, case_sens)
        && value.contains(valueSearch, case_sens)
        && address.startsWith(addressSearch, Qt::CaseSensitive);   // Address is always case-sensitive
}

//
// ManageNamesPage
//

const static int COLUMN_WIDTH_NAME = 300,
                 COLUMN_WIDTH_ADDRESS = 256,
                 COLUMN_WIDTH_EXPIRES_IN = 100;

ManageNamesPage::ManageNamesPage(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ManageNamesPage),
    model(0),
    walletModel(0),
    proxyModel(0)
{
    ui->setupUi(this);

    // Context menu actions
    QAction *copyNameAction = new QAction(tr("Copy &Name"), this);
    QAction *copyValueAction = new QAction(tr("Copy &Value"), this);
    QAction *copyAddressAction = new QAction(tr("Copy &Address"), this);

    // Build context menu
    contextMenu = new QMenu();
    contextMenu->addAction(copyNameAction);
    contextMenu->addAction(copyValueAction);
    contextMenu->addAction(copyAddressAction);

    // Connect signals for context menu actions
    connect(copyNameAction, SIGNAL(triggered()), this, SLOT(onCopyNameAction()));
    connect(copyValueAction, SIGNAL(triggered()), this, SLOT(onCopyValueAction()));
    connect(copyAddressAction, SIGNAL(triggered()), this, SLOT(onCopyAddressAction()));

    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    ui->tableView->setEditTriggers(QAbstractItemView::NoEditTriggers);

    // Connect signal for QComboBox wich select tx type
    connect(ui->txTypeSelector, SIGNAL(currentIndexChanged(QString)), this, SLOT(onTxTypeChanged(QString)));

    // Reset gui sizes and visibility (for name new)
    ui->registerAddress->setDisabled(true);

    // Catch focus changes to make the appropriate button the default one (Submit or Configure)
    ui->registerName->installEventFilter(this);
    ui->registerValue->installEventFilter(this);
    ui->txTypeSelector->installEventFilter(this);
    ui->submitNameButton->installEventFilter(this);
    ui->tableView->installEventFilter(this);
    ui->nameFilter->installEventFilter(this);
    ui->valueFilter->installEventFilter(this);
    ui->addressFilter->installEventFilter(this);

    ui->registerName->setMaxLength(MAX_NAME_LENGTH);
    ui->registerValue->setMaxLength(MAX_VALUE_LENGTH);

    ui->nameFilter->setMaxLength(MAX_NAME_LENGTH);
    ui->valueFilter->setMaxLength(GUI_MAX_VALUE_LENGTH);
    GUIUtil::setupAddressWidget(ui->addressFilter, this);

#if QT_VERSION >= 0x040700
    /* Do not move this to the XML file, Qt before 4.7 will choke on it */
    ui->nameFilter->setPlaceholderText(tr("Name filter"));
    ui->valueFilter->setPlaceholderText(tr("Value filter"));
    ui->addressFilter->setPlaceholderText(tr("Address filter"));
#endif

    ui->nameFilter->setFixedWidth(COLUMN_WIDTH_NAME);
    ui->addressFilter->setFixedWidth(COLUMN_WIDTH_ADDRESS);
    ui->horizontalSpacer_ExpiresIn->changeSize(
        COLUMN_WIDTH_EXPIRES_IN + ui->tableView->verticalScrollBar()->sizeHint().width()

#ifdef Q_OS_MAC
        // Not sure if this is needed, but other Mac code adds 2 pixels to scroll bar width;
        // see transactionview.cpp, search for verticalScrollBar()->sizeHint()
        + 2
#endif

        ,
        ui->horizontalSpacer_ExpiresIn->sizeHint().height(),
        QSizePolicy::Fixed);
}

ManageNamesPage::~ManageNamesPage()
{
    delete ui;
}

void ManageNamesPage::setModel(WalletModel *walletModel)
{
    this->walletModel = walletModel;
    model = walletModel->getNameTableModel();

    proxyModel = new NameFilterProxyModel(this);
    proxyModel->setSourceModel(model);
    proxyModel->setDynamicSortFilter(true);
    proxyModel->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxyModel->setFilterCaseSensitivity(Qt::CaseInsensitive);

    ui->tableView->setModel(proxyModel);
    ui->tableView->sortByColumn(0, Qt::AscendingOrder);

    ui->tableView->horizontalHeader()->setHighlightSections(false);

    // Set column widths
    ui->tableView->horizontalHeader()->resizeSection(
            NameTableModel::Name, COLUMN_WIDTH_NAME);
    ui->tableView->horizontalHeader()->setResizeMode(
            NameTableModel::Value, QHeaderView::Stretch);
    ui->tableView->horizontalHeader()->resizeSection(
            NameTableModel::Address, COLUMN_WIDTH_ADDRESS);
    ui->tableView->horizontalHeader()->resizeSection(
            NameTableModel::ExpiresIn, COLUMN_WIDTH_EXPIRES_IN);

    connect(ui->tableView->selectionModel(), SIGNAL(selectionChanged(QItemSelection,QItemSelection)),
            this, SLOT(selectionChanged()));

    connect(ui->nameFilter, SIGNAL(textChanged(QString)), this, SLOT(changedNameFilter(QString)));
    connect(ui->valueFilter, SIGNAL(textChanged(QString)), this, SLOT(changedValueFilter(QString)));
    connect(ui->addressFilter, SIGNAL(textChanged(QString)), this, SLOT(changedAddressFilter(QString)));

    selectionChanged();
}

void ManageNamesPage::changedNameFilter(const QString &filter)
{
    if (!proxyModel)
        return;
    proxyModel->setNameSearch(filter);
}

void ManageNamesPage::changedValueFilter(const QString &filter)
{
    if (!proxyModel)
        return;
    proxyModel->setValueSearch(filter);
}

void ManageNamesPage::changedAddressFilter(const QString &filter)
{
    if (!proxyModel)
        return;
    proxyModel->setAddressSearch(filter);
}

//TODO finish this
void ManageNamesPage::on_submitNameButton_clicked()
{
    if (!walletModel)
        return;

    QString name = ui->registerName->text();
    QString value = ui->registerValue->text();
    int days = ui->registerDays->text().toInt();
    QString txType = ui->txTypeSelector->currentText();
    QString newAddress = ui->registerAddress->text();
    if (txType == "NAME_UPDATE")
        newAddress = ui->registerAddress->text();

    if (name == "")
    {
        QMessageBox::critical(this, tr("Name is empty"), tr("Enter name please"));
        return;
    }

    if (value == "" && (txType == "NAME_NEW" || txType == "NAME_UPDATE"))
    {
        QMessageBox::critical(this, tr("Value is empty"), tr("Enter value please"));
        return;
    }

    // TODO: name needs more exhaustive syntax checking, Unicode characters etc.
    // TODO: maybe it should be done while the user is typing (e.g. show/hide a red notice below the input box)
    if (name != name.simplified() || name.contains(" "))
    {
        if (QMessageBox::Yes != QMessageBox::warning(this, tr("Name registration warning"),
              tr("The name you entered contains whitespace characters. It is probably invalid. Are you sure you want to use this name?"),
              QMessageBox::Yes | QMessageBox::Cancel,
              QMessageBox::Cancel))
        {
            return;
        }
    }

    if (QMessageBox::Yes != QMessageBox::question(this, tr("Confirm name registration"),
          tr("This will issue a %1.").arg(txType),
          QMessageBox::Yes | QMessageBox::Cancel,
          QMessageBox::Cancel))
    {
        return;
    }

    WalletModel::UnlockContext ctx(walletModel->requestUnlock());
    if (!ctx.isValid())
        return;

    QString err_msg;

    try
    {
        NameTxReturn res;
        int nHeight;
        ChangeType status;
        if (txType == "NAME_NEW")
        {
            nHeight = NameTableEntry::NAME_NEW;
            status = CT_NEW;
            res = walletModel->nameNew(name, value, days);
        }
        else if (txType == "NAME_UPDATE")
        {
            nHeight = NameTableEntry::NAME_UPDATE;
            status = CT_UPDATED;
            res = walletModel->nameUpdate(name, value, days, newAddress);
        }
        else if (txType == "NAME_DELETE")
        {
            nHeight = NameTableEntry::NAME_DELETE;
            status = CT_UPDATED; //we still want to display this name until it is delited
            res = walletModel->nameDelete(name);
        }

        if (res.ok)
        {
            ui->registerName->setText("");
            ui->registerValue->setText("");
            ui->submitNameButton->setDefault(true);

            int newRowIndex;
            // FIXME: CT_NEW may have been sent from nameNew (via transaction).
            // Currently updateEntry is modified so it does not complain
            model->updateEntry(name, value, QString::fromStdString(res.address), nHeight, status, &newRowIndex);
            ui->tableView->selectRow(newRowIndex);
            ui->tableView->setFocus();
            return;
        }

        err_msg = QString::fromStdString(res.err_msg);
    }
    catch (std::exception& e)
    {
        err_msg = e.what();
    }

    if (err_msg == "ABORTED")
        return;

    QMessageBox::warning(this, tr("Name registration failed"), err_msg);
}

bool ManageNamesPage::eventFilter(QObject *object, QEvent *event)
{
    if (event->type() == QEvent::FocusIn)
    {
        if (object == ui->registerName || object == ui->submitNameButton)
        {
            ui->submitNameButton->setDefault(true);
        }
        else if (object == ui->tableView)
        {
            ui->submitNameButton->setDefault(false);
        }
    }
    return QDialog::eventFilter(object, event);
}

void ManageNamesPage::selectionChanged()
{
    // Set button states based on selected tab and selection
//    QTableView *table = ui->tableView;
//    if(!table->selectionModel())
//        return;
}

void ManageNamesPage::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if (index.isValid())
        contextMenu->exec(QCursor::pos());
}

void ManageNamesPage::onCopyNameAction()
{
    GUIUtil::copyEntryData(ui->tableView, NameTableModel::Name);
}

void ManageNamesPage::onCopyValueAction()
{
    GUIUtil::copyEntryData(ui->tableView, NameTableModel::Value);
}

void ManageNamesPage::onCopyAddressAction()
{
    GUIUtil::copyEntryData(ui->tableView, NameTableModel::Address);
}

void ManageNamesPage::onTxTypeChanged(const QString &txType)
{
    if (txType == "NAME_NEW")
    {
        ui->registerAddress->setDisabled(true);
        ui->registerValue->setEnabled(true);
    }
    else if (txType == "NAME_UPDATE")
    {
        ui->registerAddress->setEnabled(true);
        ui->registerValue->setEnabled(true);
    }
    else if (txType == "NAME_DELETE")
    {
        ui->registerAddress->setDisabled(true);
        ui->registerValue->setDisabled(true);
    }
    return;
}

void ManageNamesPage::exportClicked()
{
    // CSV is currently the only supported format
    QString filename = GUIUtil::getSaveFileName(
            this,
            tr("Export Registered Names Data"), QString(),
            tr("Comma separated file (*.csv)"));

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);
    writer.setModel(proxyModel);
    // name, column, role
    writer.addColumn("Name", NameTableModel::Name, Qt::EditRole);
    writer.addColumn("Value", NameTableModel::Value, Qt::EditRole);
    writer.addColumn("Address", NameTableModel::Address, Qt::EditRole);
    writer.addColumn("Expires In", NameTableModel::ExpiresIn, Qt::EditRole);

    if(!writer.write())
    {
        QMessageBox::critical(this, tr("Error exporting"), tr("Could not write to file %1.").arg(filename),
                              QMessageBox::Abort, QMessageBox::Abort);
    }
}
