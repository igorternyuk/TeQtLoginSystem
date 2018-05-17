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
