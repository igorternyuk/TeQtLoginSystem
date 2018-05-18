#include "usermanagmentform.hpp"
#include "ui_usermanagmentform.h"
#include "registerUserDialog.hpp"
#include <QCheckBox>
#include <QMessageBox>
#include <QSqlTableModel>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>

UserManagmentForm::UserManagmentForm(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::UserManagmentForm)
{
    ui->setupUi(this);
    mModelUser = new QSqlTableModel(this);
    mModelUser->setTable("user");
    mModelUser->setHeaderData(0, Qt::Horizontal, "ID user");
    mModelUser->setHeaderData(1, Qt::Horizontal, "user name");
    mModelUser->setHeaderData(2, Qt::Horizontal, "user password");
    mModelUser->select();
    ui->tableViewUser->setModel(mModelUser);
    ui->tableViewUser->setContextMenuPolicy(Qt::ActionsContextMenu);
    ui->tableViewUser->addAction(ui->action_remove_user);

    mModelAdmin = new QSqlTableModel(this);
    mModelAdmin->setTable("admin");
    mModelAdmin->setHeaderData(0, Qt::Horizontal, "ID admin");
    mModelAdmin->setHeaderData(1, Qt::Horizontal, "admin name");
    mModelAdmin->setHeaderData(2, Qt::Horizontal, "admin password");

    mModelAdmin->select();
    ui->tableViewAdmin->setModel(mModelAdmin);
    ui->tableViewAdmin->setContextMenuPolicy(Qt::ActionsContextMenu);
    ui->tableViewAdmin->addAction(ui->action_remove_admin);
}

UserManagmentForm::~UserManagmentForm()
{
    delete ui;
}

void UserManagmentForm::on_btnRegister_clicked()
{
    RegisterUserDialog dialog;
    if(dialog.exec() == RegisterUserDialog::Accepted)
    {
        qDebug() << "Accepted";
        User user = dialog.getUser();
        QSqlQuery query;
        QString cmd = QString("INSERT INTO %1 (name, password) VALUES('%2', '%3');")
                .arg(dialog.getIsAdminCheckBox()->isChecked()
                     ? "admin" : "user")
                .arg(user.name())
                .arg(user.password());
        qDebug() << cmd;
        if(query.exec(cmd))
        {
            mModelUser->select();
            mModelAdmin->select();
            QMessageBox::information(this, "Success", "Register was successfully added");
        }
        else
        {
            QMessageBox::critical(this, "Error", query.lastError().text());
        }
    }
}


void UserManagmentForm::on_tableViewUser_clicked(const QModelIndex &index)
{

}

void UserManagmentForm::on_tableViewAdmin_clicked(const QModelIndex &index)
{

}

void UserManagmentForm::on_action_remove_user_triggered()
{
    int reply = QMessageBox::question(this, "Confirm deleting, please",
                                      "Do you really want to delete selectred user?",
                                      QMessageBox::Yes | QMessageBox::No);
    if(reply == QMessageBox::Yes)
    {
        mModelUser->removeRow(ui->tableViewUser->currentIndex().row());
        mModelUser->select();
    }
}

void UserManagmentForm::on_action_remove_admin_triggered()
{
    int reply = QMessageBox::question(this, "Confirm deleting, please",
                                      "Do you really want to delete selectred admin?",
                                      QMessageBox::Yes | QMessageBox::No);
    if(reply == QMessageBox::Yes)
    {
        mModelAdmin->removeRow(ui->tableViewUser->currentIndex().row());
        mModelAdmin->select();
    }
}

void UserManagmentForm::on_btnSearchUser_clicked()
{
    QString searchPattern = ui->lineEditSearchUser->text();
    mModelUser->setFilter(QString(" name LIKE '%%1%'").arg(searchPattern));
    mModelUser->select();
}

void UserManagmentForm::on_btnLoadFullUserList_clicked()
{
    mModelUser->setFilter("");
    mModelUser->select();
}
