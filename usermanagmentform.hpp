#ifndef USERMANAGMENTFORM_HPP
#define USERMANAGMENTFORM_HPP

#include <QWidget>
#include "dbmanager.hpp"

namespace Ui
{
    class UserManagmentForm;
}

class QSqlTableModel;

class UserManagmentForm : public QWidget
{
    Q_OBJECT

public:
    explicit UserManagmentForm(DbManager& manager,
                               QWidget *parent = nullptr);
    ~UserManagmentForm();

private slots:
    void on_btnRegister_clicked();
    void on_tableViewUser_clicked(const QModelIndex &index);
    void on_tableViewAdmin_clicked(const QModelIndex &index);
    void on_action_remove_user_triggered();
    void on_action_remove_admin_triggered();
    void on_btnSearchUser_clicked();
    void on_btnLoadFullUserList_clicked();

private:
    Ui::UserManagmentForm *ui;
    DbManager& mDbManager;
    QSqlTableModel *mModelUser;
    QSqlTableModel *mModelAdmin;
};

#endif // USERMANAGMENTFORM_HPP
