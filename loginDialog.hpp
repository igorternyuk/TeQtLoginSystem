#ifndef DIALOG_HPP
#define DIALOG_HPP

#include "tecipher.hpp"
#include "dbmanager.hpp"
#include <QDialog>

namespace Ui
{
    class Dialog;
}

class LoginDialog : public QDialog
{
    Q_OBJECT

public:
    enum class LoginType
    {
        RegularUser,
        Administrator
    };
    explicit LoginDialog(DbManager &manager, QWidget *parent = nullptr);
    ~LoginDialog();

    LoginType getLoginType() const;
    static QString getPassword();
    static QString encrypt(const QString &text);
    static QString decrypt(const QString &text);

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_btnRegisterAdmin_clicked();

private:
    Ui::Dialog *ui;
    LoginType mLoginType;
    DbManager &mDbManager;
    void checkIfAdminExists();
};

#endif // DIALOG_HPP
