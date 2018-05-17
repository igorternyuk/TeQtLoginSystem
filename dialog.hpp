#ifndef DIALOG_HPP
#define DIALOG_HPP

#include <QDialog>
#include "tecipher.hpp"

namespace Ui
{
    class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    enum class LoginType
    {
        RegularUser,
        Administrator
    };
    explicit Dialog(QWidget *parent = nullptr);
    ~Dialog();

    LoginType getLoginType() const;

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_btnRegisterAdmin_clicked();

private:

    Ui::Dialog *ui;
    TeCipher mCipher;
    LoginType mLoginType;
    void checkIfAdminExists();
};

#endif // DIALOG_HPP
