#include "dbmanager.hpp"
#include "loginDialog.hpp"
#include <QVariant>
#include <QSqlQuery>
#include <QSqlError>
#ifdef DEBUG
#include <QDebug>
#endif
#include <stdexcept>

DbManager::DbManager()
{}

bool DbManager::insertUser(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_INSERT_USER)
            .arg(user.type() == User::Type::Administrator ? "admin" : "user")
            .arg(user.name()).arg(user.password());
#ifdef DEBUG
    qDebug() << cmd;
#endif
    return query.exec(cmd);
}

bool DbManager::checkIfUserExists(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_CHECK_IF_USER_EXISTS)
            .arg(user.type() == User::Type::Administrator ? "admin" : "user")
            .arg(user.name());
#ifdef DEBUG
    qDebug() << cmd;
#endif
    query.exec(cmd);
    bool userFound = false;
    while(query.next())
    {
        QString encryptedPassword = query.value(2).toString();
        QString decryptedPassword = LoginDialog::decrypt(encryptedPassword);
        if(user.password() == decryptedPassword)
        {
            userFound = true;
            break;
        }
    }
    return userFound;
}

int DbManager::countAdmins()
{
    QSqlQuery query;
    query.exec(SQL_COUNT_ADMINS);
    query.next();
    return query.value(0).toInt();
}

QString DbManager::getLastError() const
{
    return mDb.lastError().text();
}


void DbManager::createDatabase()
{
    if(!QSqlDatabase::isDriverAvailable(DB_DRIVER))
    {
        throw std::runtime_error("SQLite driver is not available");
    }

    mDb = QSqlDatabase::addDatabase(DB_DRIVER);
    mDb.setDatabaseName(DB_NAME);

    if(!mDb.open())
    {
        throw std::runtime_error(mDb.lastError().text().toStdString());
    }
}

void DbManager::configureDatabase()
{
    QSqlQuery query;
    if(!query.exec(SQL_CREATE_USER_TABLE))
    {
        throw std::runtime_error(query.lastError().text().toStdString());
    }
    if(!query.exec(SQL_CREATE_ADMIN_TABLE))
    {
        throw std::runtime_error(query.lastError().text().toStdString());
    }
}
