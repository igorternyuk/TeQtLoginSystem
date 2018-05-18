#include "dbmanager.hpp"
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>
#include <stdexcept>

DbManager::DbManager()
{

}

bool DbManager::insertUser(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_INSERT_USER)
            .arg(user.name()).arg(user.password());
    qDebug() << cmd;
    return query.exec(cmd);
}

bool DbManager::insertAdmin(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_INSERT_ADMIN)
            .arg(user.name()).arg(user.password());
    qDebug() << cmd;
    return query.exec(cmd);
}

bool DbManager::checkIfUserExists(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_CHECK_IF_USER_EXISTS)
            .arg(user.name()).arg(user.password());
    query.exec(cmd);
    query.next();
    const int count = query.value(0).toInt();
    return count > 0;
}

bool DbManager::checkIfAdminExists(const User &user)
{
    QSqlQuery query;
    QString cmd = QString(SQL_CHECK_IF_ADMIN_EXISTS)
            .arg(user.name()).arg(user.password());
    query.exec(cmd);
    query.next();
    const int count = query.value(0).toInt();
    return count > 0;
}

int DbManager::countAdmins()
{
    QSqlQuery query;
    query.exec(SQL_COUNT_ADMINS);
    query.next();
    return query.value(0).toInt();
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
