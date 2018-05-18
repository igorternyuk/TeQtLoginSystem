#ifndef DBMANAGER_H
#define DBMANAGER_H

#include "user.hpp"
#include "admin.hpp"
#include <QSqlDatabase>
#include <QString>

class DbManager
{
public:
    explicit DbManager();
    void createDatabase();
    void configureDatabase();
    bool insertUser(const User &user);
    bool insertAdmin(const User &user);
    bool checkIfUserExists(const User &user);
    bool checkIfAdminExists(const User &user);
    int countAdmins();
private:
    const QString DB_DRIVER = "QSQLITE";
    const QString DB_NAME = "./data.db";
    const QString SQL_CREATE_USER_TABLE = "CREATE TABLE IF NOT EXISTS user"
                                          " (id INTEGER PRIMARY KEY AUTOINCREMENT"
                                          " NOT NULL, name TEXT NOT NULL UNIQUE,"
                                          " password TEXT NOT NULL);";
    const QString SQL_CREATE_ADMIN_TABLE = "CREATE TABLE IF NOT EXISTS admin"
                                           " (id INTEGER PRIMARY KEY AUTOINCREMENT"
                                           " NOT NULL, name TEXT NOT NULL UNIQUE,"
                                           " password TEXT NOT NULL);";
    const QString SQL_INSERT_ADMIN = "INSERT INTO admin (name, password)"
                                     " VALUES('%1', '%2');";
    const QString SQL_INSERT_USER = "INSERT INTO user (name, password)"
                                     " VALUES('%1', '%2');";
    const QString SQL_COUNT_ADMINS = "SELECT count(*) from admin";
    const QString SQL_CHECK_IF_USER_EXISTS = "SELECT count(*) from user WHERE"
                                             " name LIKE '%1'";
    const QString SQL_CHECK_IF_ADMIN_EXISTS = "SELECT count(*) from admin WHERE"
                                              " name LIKE '%1'";
    QSqlDatabase mDb;

};

#endif // DBMANAGER_H
