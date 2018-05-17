#include "registerAdminDialog.hpp"
#include "ui_registerAdminDialog.h"
#include <QMessageBox>

RegisterAdminDialog::RegisterAdminDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::RegisterAdminDialog)
{
    ui->setupUi(this);
    ui->lineEditPassword->setEchoMode(QLineEdit::Password);
    ui->lineEditRepeatPassword->setEchoMode(QLineEdit::Password);
}

RegisterAdminDialog::~RegisterAdminDialog()
{
    delete ui;
}

Admin RegisterAdminDialog::admin() const
{
    return mAdmin;
}

void RegisterAdminDialog::on_buttonBox_accepted()
{
    mAdmin.setId(1);
    mAdmin.setName(ui->lineEditName->text());
    mAdmin.setPassword(ui->lineEditPassword->text());
    if(ui->lineEditPassword->text() != ui->lineEditRepeatPassword->text())
    {
        QMessageBox::critical(this, "Password error", "Password mismatch");
        return;
    }
    accept();
}

void RegisterAdminDialog::on_buttonBox_rejected()
{
    reject();
}
