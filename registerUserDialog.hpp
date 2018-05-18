#ifndef REGISTERADMINDIALOG_HPP
#define REGISTERADMINDIALOG_HPP

#include "user.hpp"
#include <QDialog>

namespace Ui
{
    class RegisterAdminDialog;
}

class QCheckBox;
class RegisterUserDialog : public QDialog
{
    Q_OBJECT

public:
    explicit RegisterUserDialog(QWidget *parent = nullptr);
    ~RegisterUserDialog();

    User getUser() const;
    QCheckBox* getIsAdminCheckBox() const;

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    User mUser;
    Ui::RegisterAdminDialog *ui;
};

#endif // REGISTERADMINDIALOG_HPP
