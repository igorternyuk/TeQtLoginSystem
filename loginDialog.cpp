#include "loginDialog.hpp"
#include "ui_dialog.h"
#include "registerUserDialog.hpp"
#include <QSqlQuery>
#include <QMessageBox>
#include <QCheckBox>
#ifdef DEBUG
#include <QDebug>
#endif

LoginDialog::LoginDialog(DbManager &manager, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog),
    mDbManager(manager)
{
    ui->setupUi(this);
    ui->lineEditUserPassword->setEchoMode(QLineEdit::Password);
    checkIfAdminExists();
}

LoginDialog::~LoginDialog()
{
    delete ui;
}

void LoginDialog::on_buttonBox_accepted()
{
    User user(-1, ui->lineEditUsername->text(),
              ui->lineEditUserPassword->text());
    bool isAdmin = ui->radioBtnAdministrator->isChecked();
    if(isAdmin)
    {
        user.setType(User::Type::Administrator);
    }

    if(!mDbManager.checkIfUserExists(user))
    {
        QMessageBox::warning(this, "Authentication error",
                             "Incorrect username or password");
        reject();
        return;
    }
    mLoginType = isAdmin ? LoginType::Administrator : LoginType::RegularUser;
    accept();
}

void LoginDialog::on_buttonBox_rejected()
{
    reject();
}

void LoginDialog::on_btnRegisterAdmin_clicked()
{
    RegisterUserDialog dialog;
    dialog.getIsAdminCheckBox()->setChecked(true);
    dialog.getIsAdminCheckBox()->setEnabled(false);
    if(dialog.exec() == RegisterUserDialog::Accepted)
    {
        User user = dialog.getUser();
        QString userpass = user.password();
        QString encryptedUserPass = LoginDialog::encrypt(userpass);
        user.setPassword(encryptedUserPass);
        user.setType(User::Type::Administrator);
        if(mDbManager.insertUser(user))
        {
            QMessageBox::information(this, "Success",
                                     "New admin was successfully registered");
        }
        else
        {
            QMessageBox::critical(this, "Failure",
                                  "Could not insert new admin: "
                                  + mDbManager.getLastError());
        }
        checkIfAdminExists();
    }
}

QString LoginDialog::getPassword()
{
    return QString("Un gitano loco me dije: Los caballos tocan la guitarra muy bien!!!");
}

QString LoginDialog::encrypt(const QString &text)
{
    TeCipher cipher;
    cipher.loadPublicKeyByteArrayFromFile("public.pem");
    cipher.loadPrivateKeyByteArrayFromFile("private.pem");
    QString password = getPassword();
    QString encryptedText;
    cipher.encryptPlainTextWithCombinedMethod(password, text,
                                               encryptedText);
    return encryptedText;
}

QString LoginDialog::decrypt(const QString &text)
{
    TeCipher cipher;
    cipher.loadPublicKeyByteArrayFromFile("public.pem");
    cipher.loadPrivateKeyByteArrayFromFile("private.pem");
    QString password = getPassword();
    QString decryptedText;
    cipher.decryptPlainTextWithCombinedMethod(password, text,
                                               decryptedText);
    return decryptedText;
}

LoginDialog::LoginType LoginDialog::getLoginType() const
{
    return mLoginType;
}

void LoginDialog::checkIfAdminExists()
{
    if(mDbManager.countAdmins() == 0)
    {
        ui->btnRegisterAdmin->setEnabled(true);
    }
    else
    {
        ui->btnRegisterAdmin->setEnabled(false);
    }
}
