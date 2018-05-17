#include "dialog.hpp"
#include "ui_dialog.h"
#include "registerAdminDialog.hpp"
#include <QSqlQuery>
#include <QMessageBox>
#include <QDebug>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    ui->lineEditUserPassword->setEchoMode(QLineEdit::Password);

    mCipher.loadPublicKeyByteArrayFromFile("public.pem");
    mCipher.loadPrivateKeyByteArrayFromFile("private.pem");

    checkIfAdminExists();
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_buttonBox_accepted()
{

    if(ui->radioBtnRegularUser->isChecked())
    {
        QSqlQuery query;
        User user(-1, ui->lineEditUsername->text(),
                  ui->lineEditUserPassword->text());
        QString cmd = QString("SELECT count(*) from user WHERE"
                              " name LIKE '%1' AND password LIKE '%2'")
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
        Admin admin(-1, ui->lineEditUsername->text(),
                    ui->lineEditUserPassword->text());
        QString cmd = QString("SELECT count(*) from admin WHERE"
                              " name LIKE '%1' AND password LIKE '%2'")
                .arg(admin.name()).arg(admin.password());
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

void Dialog::on_buttonBox_rejected()
{
    reject();
}

void Dialog::on_btnRegisterAdmin_clicked()
{
    qDebug() << "Registering the new admin";
    RegisterAdminDialog dialog;
    if(dialog.exec() == RegisterAdminDialog::Accepted)
    {
        qDebug() << "Accepted";
        Admin admin = dialog.admin();
        QSqlQuery query;
        QString cmd = QString("INSERT INTO admin (1,'%1', '%2');")
                .arg(admin.name()).arg(admin.password());
        qDebug() << cmd;
        query.exec(cmd);
        checkIfAdminExists();
    }
}

Dialog::LoginType Dialog::getLoginType() const
{
    return mLoginType;
}

void Dialog::checkIfAdminExists()
{
    QSqlQuery query;
    query.exec("SELECT count(*) from admin");
    query.next();
    const int adminCount = query.value(0).toInt();
    qDebug() << "Checking if admin already exists";
    qDebug() << "adminCount " << adminCount;
    if(adminCount != 0)
    {
        ui->btnRegisterAdmin->setEnabled(false);
    }
    else
    {
        ui->btnRegisterAdmin->setEnabled(true);
    }

}
