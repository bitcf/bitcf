#include "guiutil.h"
#include "bitcoinaddressvalidator.h"
#include "walletmodel.h"
#include "bitcoinunits.h"

#include "util.h"
#include "init.h"

#include <QString>
#include <QDateTime>
#include <QDoubleValidator>
#include <QFont>
#include <QLineEdit>
#include <QUrl>
#include <QTextDocument> // For Qt::escape
#include <QAbstractItemView>
#include <QApplication>
#include <QClipboard>
#include <QFileDialog>
#include <QDesktopServices>
#include <QThread>

#include <boost/filesystem.hpp>
//#include <boost/filesystem/fstream.hpp>

namespace GUIUtil {

QString dateTimeStr(const QDateTime &date)
{
    return date.date().toString(Qt::SystemLocaleShortDate) + QString(" ") + date.toString("hh:mm");
}

QString dateTimeStr(qint64 nTime)
{
    return dateTimeStr(QDateTime::fromTime_t((qint32)nTime));
}

QFont bitcoinAddressFont()
{
    QFont font("Monospace");
    font.setStyleHint(QFont::TypeWriter);
    return font;
}

void setupAddressWidget(QLineEdit *widget, QWidget *parent)
{
    widget->setMaxLength(BitcoinAddressValidator::MaxAddressLength);
    widget->setValidator(new BitcoinAddressValidator(parent));
    widget->setFont(bitcoinAddressFont());
}

void setupAmountWidget(QLineEdit *widget, QWidget *parent)
{
    QDoubleValidator *amountValidator = new QDoubleValidator(parent);
    amountValidator->setDecimals(8);
    amountValidator->setBottom(0.0);
    widget->setValidator(amountValidator);
    widget->setAlignment(Qt::AlignRight|Qt::AlignVCenter);
}

bool parseBitcoinURI(const QUrl &uri, SendCoinsRecipient *out)
{
    if(uri.scheme() != QString("bitcf"))
        return false;

    SendCoinsRecipient rv;
    rv.address = uri.path();
    rv.amount = 0;
    QList<QPair<QString, QString> > items = uri.queryItems();
    for (QList<QPair<QString, QString> >::iterator i = items.begin(); i != items.end(); i++)
    {
        bool fShouldReturnFalse = false;
        if (i->first.startsWith("req-"))
        {
            i->first.remove(0, 4);
            fShouldReturnFalse = true;
        }

        if (i->first == "label")
        {
            rv.label = i->second;
            fShouldReturnFalse = false;
        }
        else if (i->first == "amount")
        {
            if(!i->second.isEmpty())
            {
                if(!BitcoinUnits::parse(BitcoinUnits::BTC, i->second, &rv.amount))
                {
                    return false;
                }
            }
            fShouldReturnFalse = false;
        }

        if (fShouldReturnFalse)
            return false;
    }
    if(out)
    {
        *out = rv;
    }
    return true;
}

bool parseBitcoinURI(QString uri, SendCoinsRecipient *out)
{
    // Convert emercoin:// to emercoin:
    //
    //    Cannot handle this later, because emercoin:// will cause Qt to see the part after // as host,
    //    which will lowercase it (and thus invalidate the address).
    if(uri.startsWith("bitcf://"))
    {
        uri.replace(0, 11, "bitcf:");
    }
    QUrl uriInstance(uri);
    return parseBitcoinURI(uriInstance, out);
}

QString HtmlEscape(const QString& str, bool fMultiLine)
{
    QString escaped = Qt::escape(str);
    if(fMultiLine)
    {
        escaped = escaped.replace("\n", "<br>\n");
    }
    return escaped;
}

QString HtmlEscape(const std::string& str, bool fMultiLine)
{
    return HtmlEscape(QString::fromStdString(str), fMultiLine);
}

void copyEntryData(QAbstractItemView *view, int column, int role)
{
    if(!view || !view->selectionModel())
        return;
    QModelIndexList selection = view->selectionModel()->selectedRows(column);

    if(!selection.isEmpty())
    {
        // Copy first item
        QApplication::clipboard()->setText(selection.at(0).data(role).toString());
    }
}

QString getSaveFileName(QWidget *parent, const QString &caption,
                                 const QString &dir,
                                 const QString &filter,
                                 QString *selectedSuffixOut)
{
    QString selectedFilter;
    QString myDir;
    if(dir.isEmpty()) // Default to user documents location
    {
        myDir = QDesktopServices::storageLocation(QDesktopServices::DocumentsLocation);
    }
    else
    {
        myDir = dir;
    }
    QString result = QFileDialog::getSaveFileName(parent, caption, myDir, filter, &selectedFilter);

    /* Extract first suffix from filter pattern "Description (*.foo)" or "Description (*.foo *.bar ...) */
    QRegExp filter_re(".* \\(\\*\\.(.*)[ \\)]");
    QString selectedSuffix;
    if(filter_re.exactMatch(selectedFilter))
    {
        selectedSuffix = filter_re.cap(1);
    }

    /* Add suffix if needed */
    QFileInfo info(result);
    if(!result.isEmpty())
    {
        if(info.suffix().isEmpty() && !selectedSuffix.isEmpty())
        {
            /* No suffix specified, add selected suffix */
            if(!result.endsWith("."))
                result.append(".");
            result.append(selectedSuffix);
        }
    }

    /* Return selected suffix if asked to */
    if(selectedSuffixOut)
    {
        *selectedSuffixOut = selectedSuffix;
    }
    return result;
}

Qt::ConnectionType blockingGUIThreadConnection()
{
    if(QThread::currentThread() != QCoreApplication::instance()->thread())
    {
        return Qt::BlockingQueuedConnection;
    }
    else
    {
        return Qt::DirectConnection;
    }
}

bool checkPoint(const QPoint &p, const QWidget *w)
{
  QWidget *atW = qApp->widgetAt(w->mapToGlobal(p));
  if(!atW) return false;
  return atW->topLevelWidget() == w;
}

bool isObscured(QWidget *w)
{

  return !(checkPoint(QPoint(0, 0), w)
           && checkPoint(QPoint(w->width() - 1, 0), w)
           && checkPoint(QPoint(0, w->height() - 1), w)
           && checkPoint(QPoint(w->width() - 1, w->height() - 1), w)
           && checkPoint(QPoint(w->width()/2, w->height()/2), w));
}

void openDebugLogfile()
{
    boost::filesystem::path pathDebug = GetDataDir() / "debug.log";

    /* Open debug.log with the associated application */
    if (boost::filesystem::exists(pathDebug))
        QDesktopServices::openUrl(QUrl::fromLocalFile(QString::fromStdString(pathDebug.string())));
}

HelpMessageBox::HelpMessageBox(QWidget *parent) :
    QMessageBox(parent)
{
    header = tr("Bitcf-Qt") + " " + tr("version") + " " +
        QString::fromStdString(FormatFullVersion()) + "\n\n" +
        tr("Usage:") + "\n" +
        "  bitcf-qt [" + tr("command-line options") + "]                     " + "\n";

    coreOptions = QString::fromStdString(HelpMessage());

    uiOptions = tr("UI options") + ":\n" +
        "  -lang=<lang>           " + tr("Set language, for example \"de_DE\" (default: system locale)") + "\n" +
        "  -min                   " + tr("Start minimized") + "\n" +
        "  -splash                " + tr("Show splash screen on startup (default: 1)") + "\n";

    setWindowTitle(tr("Bitcf-Qt"));
    setTextFormat(Qt::PlainText);
    // setMinimumWidth is ignored for QMessageBox so put in non-breaking spaces to make it wider.
    setText(header + QString(QChar(0x2003)).repeated(50));
    setDetailedText(coreOptions + "\n" + uiOptions);
}

} // namespace GUIUtil

