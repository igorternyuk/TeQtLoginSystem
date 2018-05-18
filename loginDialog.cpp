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

    mCipher.loadPublicKeyByteArrayFromFile("public.pem");
    mCipher.loadPrivateKeyByteArrayFromFile("private.pem");

    checkIfAdminExists();
}

LoginDialog::~LoginDialog()
{
    delete ui;
}

void LoginDialog::on_buttonBox_accepted()
{

    if(ui->radioBtnRegularUser->isChecked())
    {
        QSqlQuery query;
        User user(-1, ui->lineEditUsername->text(),
                  ui->lineEditUserPassword->text());
        QString cmd = QString("SELECT count(*) from user WHERE"
                              " name LIKE '%1'")
                .arg(user.name()).arg(user.password());
        query.exec(cmd);
        query.next();
        const int count = query.value(0).toInt();
        if(count == 0)
        {
            QMessageBox::warning(this, "Authentication error",
                                 "Incorrect username or password");
            reject();
            return;
        }
        mLoginType = LoginType::RegularUser;
    }
    else if(ui->radioBtnAdministrator->isChecked())
    {
        QSqlQuery query;
        User user(-1, ui->lineEditUsername->text(),
                    ui->lineEditUserPassword->text());
        QString cmd = QString("SELECT count(*) from admin WHERE"
                              " name LIKE '%1' AND password LIKE '%2'")
                .arg(user.name()).arg(user.password());
        query.exec(cmd);
        query.next();
        const int adminCount = query.value(0).toInt();
        if(adminCount == 0)
        {
            QMessageBox::warning(this, "Authentication error",
                                 "Incorrect username or password");
            reject();
            return;
        }
        mLoginType = LoginType::Administrator;
    }

    if(mLoginType == LoginType::RegularUser)
    {
        QMessageBox::information(this, "Success",
                                 "You have entered as regular user");
    }
    else if(mLoginType == LoginType::Administrator)
    {
        QMessageBox::information(this, "Success",
                                 "You have entered as administrator");
    }
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

        QSqlQuery query;
        QString cmd = QString("INSERT INTO admin (name, password) VALUES('%1', '%2');")
                .arg(user.name()).arg(user.password());
        qDebug() << cmd;
        query.exec(cmd);
        checkIfAdminExists();
    }
}

QString LoginDialog::getPassword() const
{
    return QString("Parol Na Gorshke Sidel Korol");
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
