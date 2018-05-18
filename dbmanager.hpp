#ifndef DBMANAGER_H
#define DBMANAGER_H

#include "user.hpp"
#include <QSqlDatabase>
#include <QString>

class DbManager
{
public:
    explicit DbManager();
    void createDatabase();
    void configureDatabase();
    bool insertUser(const User &user);
    bool checkIfUserExists(const User &user);
    int countAdmins();
    QString getLastError() const;
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
    const QString SQL_INSERT_USER = "INSERT INTO %1 (name, password)"
                                     " VALUES('%2', '%3');";
    const QString SQL_COUNT_ADMINS = "SELECT count(*) from admin";
    const QString SQL_CHECK_IF_USER_EXISTS = "SELECT * FROM %1 WHERE"
                                             " name LIKE '%2'";
    QSqlDatabase mDb;

};

#endif // DBMANAGER_H
