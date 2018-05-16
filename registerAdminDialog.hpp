#ifndef REGISTERADMINDIALOG_HPP
#define REGISTERADMINDIALOG_HPP

#include <QDialog>

namespace Ui
{
    class RegisterAdminDialog;
}

class RegisterAdminDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RegisterAdminDialog(QWidget *parent = nullptr);
    ~RegisterAdminDialog();

private:
    Ui::RegisterAdminDialog *ui;
};

#endif // REGISTERADMINDIALOG_HPP
