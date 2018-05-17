#ifndef REGISTERADMINDIALOG_HPP
#define REGISTERADMINDIALOG_HPP

#include "admin.hpp"
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

    Admin admin() const;

private slots:
    void on_buttonBox_accepted();

    void on_buttonBox_rejected();

private:
    Admin mAdmin;
    Ui::RegisterAdminDialog *ui;
};

#endif // REGISTERADMINDIALOG_HPP
