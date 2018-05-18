#include "loginDialog.hpp"
#include "ui_dialog.h"
#include "registerUserDialog.hpp"
#include <QSqlQuery>
#include <QMessageBox>
#include <QCheckBox>
#include <QDebug>

LoginDialog::LoginDialog(DbManager manager, QWidget *parent) :
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
    bool isAdmin = ui->radioBtnAdministrator->isChecked();
    QSqlQuery query;
    User user(-1, ui->lineEditUsername->text(),
              ui->lineEditUserPassword->text());
    QString cmd = QString("SELECT * FROM %1 WHERE name LIKE '%2'")
            .arg(isAdmin ? "admin" : "user")
            .arg(user.name());
    qDebug() << cmd;
    query.exec(cmd);
    bool userFound = false;
    qDebug() << "Checking all results...";
    while(query.next())
    {
        QString encryptedPassword = query.value(2).toString();
        qDebug() << "encryptedPassword = " << encryptedPassword;
        QString decryptedPassword = LoginDialog::decrypt(encryptedPassword);
        qDebug() << "decryptedPassword = " << decryptedPassword;
        if(user.password() == decryptedPassword)
        {
            userFound = true;
            break;
        }
        qDebug() << "Password mismatch";
    }
    if(!userFound)
    {
        QMessageBox::warning(this, "Authentication error",
                             "Incorrect username or password");
        reject();
        return;
    }
    qDebug() << "User found";
    mLoginType = isAdmin ? LoginType::Administrator : LoginType::RegularUser;
    accept();
}

void LoginDialog::on_buttonBox_rejected()
{
    reject();
}

void LoginDialog::on_btnRegisterAdmin_clicked()
{
    qDebug() << "Registering the new admin";
    RegisterUserDialog dialog;
    dialog.getIsAdminCheckBox()->setChecked(true);
    dialog.getIsAdminCheckBox()->setEnabled(false);
    if(dialog.exec() == RegisterUserDialog::Accepted)
    {
        qDebug() << "Accepted";
        User user = dialog.getUser();
        QString userpass = user.password();
        qDebug() << "Admin password: " << userpass;
        QString encryptedUserPass = LoginDialog::encrypt(userpass);
        qDebug() << "Encrypted admin password: " << encryptedUserPass;
        QSqlQuery query;
        QString cmd = QString("INSERT INTO admin (name, password) VALUES('%1', '%2');")
                .arg(user.name()).arg(encryptedUserPass);
        qDebug() << cmd;
        query.exec(cmd);
        checkIfAdminExists();
    }
}

QString LoginDialog::getPassword()
{
    return QString("Parol Na Gorshke Sidel Korol");
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
    QSqlQuery query;
    query.exec("SELECT count(*) from admin");
    query.next();
    const int adminCount = query.value(0).toInt();
    qDebug() << "Checking if admin already exists";
    qDebug() << "adminCount " << adminCount;
    if(adminCount == 0)
    {
        ui->btnRegisterAdmin->setEnabled(true);
    }
    else
    {
        ui->btnRegisterAdmin->setEnabled(false);
    }
}
