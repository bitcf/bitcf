#ifndef CLICKABLELABEL_H
#define CLICKABLELABEL_H

#include <QLabel>

// emercoin : to ensure that we can click on lock icon in GUI

class ClickableLockLabel : public QLabel
{
    Q_OBJECT

public:
    ClickableLockLabel() : QLabel() {}
    ~ClickableLockLabel() {}

signals:
    void clicked();

protected:
    void mousePressEvent(QMouseEvent * event)
    {
        QLabel::mousePressEvent(event);
        emit clicked();
    }
};

#endif // CLICKABLELABEL_H
