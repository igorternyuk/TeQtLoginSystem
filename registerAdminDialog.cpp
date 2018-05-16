#include "registerAdminDialog.hpp"
#include "ui_registerAdminDialog.h"

RegisterAdminDialog::RegisterAdminDialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::RegisterAdminDialog)
{
    ui->setupUi(this);
}

RegisterAdminDialog::~RegisterAdminDialog()
{
    delete ui;
}
