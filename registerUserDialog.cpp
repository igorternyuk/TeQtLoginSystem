#include "registerUserDialog.hpp"
#include "ui_registerUserDialog.h"
#include <QCheckBox>
#include <QMessageBox>

RegisterUserDialog::RegisterUserDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::RegisterAdminDialog)
{
    ui->setupUi(this);
    ui->lineEditPassword->setEchoMode(QLineEdit::Password);
    ui->lineEditRepeatPassword->setEchoMode(QLineEdit::Password);
}

RegisterUserDialog::~RegisterUserDialog()
{
    delete ui;
}

User RegisterUserDialog::getUser() const
{
    return mUser;
}

QCheckBox *RegisterUserDialog::getIsAdminCheckBox() const
{
    return ui->checkBoxIsAdmin;
}

void RegisterUserDialog::on_buttonBox_accepted()
{
    mUser.setId(1);
    mUser.setName(ui->lineEditName->text());
    mUser.setPassword(ui->lineEditPassword->text());
    if(ui->lineEditPassword->text() != ui->lineEditRepeatPassword->text())
    {
        QMessageBox::critical(this, "Password error", "Password mismatch");
        return;
    }
    accept();
}

void RegisterUserDialog::on_buttonBox_rejected()
{
    reject();
}
