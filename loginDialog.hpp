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
    explicit LoginDialog(DbManager manager, QWidget *parent = nullptr);
    ~LoginDialog();

    LoginType getLoginType() const;
    QString getPassword() const;

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_btnRegisterAdmin_clicked();

private:
    Ui::Dialog *ui;
    TeCipher mCipher;
    LoginType mLoginType;
    DbManager mDbManager;
    //const QString mPassword = "Parol Na Gorshke Sidel Korol";
    void checkIfAdminExists();
};

#endif // DIALOG_HPP
