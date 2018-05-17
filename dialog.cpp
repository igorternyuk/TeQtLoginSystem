#include "dialog.hpp"
#include "ui_dialog.h"
#include "registerAdminDialog.hpp"
#include <QSqlQuery>
#include <QMessageBox>

Dialog::Dialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Dialog)
{
    ui->setupUi(this);
    ui->lineEditUserPassword->setEchoMode(QLineEdit::Password);
    checkIfAdminExists();
}

Dialog::~Dialog()
{
    delete ui;
}

void Dialog::on_buttonBox_accepted()
{
    LoginType loginType;
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
            return;
        }
        loginType = LoginType::RegularUser;
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
            return;
        }
        loginType = LoginType::Administrator;
    }

    if(loginType == LoginType::RegularUser)
    {
        QMessageBox::information(this, "Success",
                                 "You have entered as regular user");
    }
    else if(loginType == LoginType::Administrator)
    {
        QMessageBox::information(this, "Success",
                                 "You have entered as administrator");
    }
}

void Dialog::on_buttonBox_rejected()
{
    close();
}

void Dialog::on_btnRegisterAdmin_clicked()
{
    RegisterAdminDialog dialog;
    if(dialog.exec() == RegisterAdminDialog::Accepted)
    {
        Admin admin = dialog.admin();
        QSqlQuery query;
        QString cmd = QString("INSERT INTO admin ('%1', '%2')")
                .arg(admin.name()).arg(admin.password());
        query.exec(cmd);
        checkIfAdminExists();
    }
}

void Dialog::checkIfAdminExists()
{
    QSqlQuery query;
    query.exec("SELECT count(*) from admin");
    query.next();
    const int adminCount = query.value(0).toInt();
    ui->btnRegisterAdmin->setEnabled(adminCount == 0);
}
