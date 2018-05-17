#include "dialog.hpp"
#include "mainwindow.hpp"
#include <QApplication>
#include <QSqlDatabase>
#include <QSqlQuery>
#include <QSqlError>
#include <QDebug>

#define DB_DRIVER "QSQLITE"
#define DB_NAME "./data.db"
#define SQL_CREATE_USER_TABLE "CREATE TABLE IF NOT EXISTS user (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL);"

#define SQL_CREATE_ADMIN_TABLE "CREATE TABLE IF NOT EXISTS admin (id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL, name TEXT NOT NULL UNIQUE, password TEXT NOT NULL);"

int createDatabase()
{
    if(!QSqlDatabase::isDriverAvailable(DB_DRIVER))
    {
        qCritical() << "SQLite driver is not available";
        return -1;
    }

    auto db = QSqlDatabase::addDatabase(DB_DRIVER);
    db.setDatabaseName(DB_NAME);

    if(!db.open())
    {
        qCritical() << "Could not open database: " << db.lastError().text();
        return -2;
    }
    return 0;
}

int configureDatabase()
{
    QSqlQuery query;
    if(!query.exec(SQL_CREATE_USER_TABLE))
    {
        qCritical() << "Could create user table: " << query.lastError();
        return -1;
    }
    if(!query.exec(SQL_CREATE_ADMIN_TABLE))
    {
        qCritical() << "Could not create admin table: " << query.lastError();
        return -2;
    }
    return 0;
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    const int result = createDatabase();
    if(result < 0)
    {
        return result;
    }

    const int configResult = configureDatabase();
    if(configResult < 0)
    {
        return configResult;
    }

    app.setStyle("fusion");
    Dialog loginDialog;

    if(loginDialog.exec() == Dialog::Rejected)
    {
        return 0;
    }

    MainWindow window(loginDialog.getLoginType());
    window.show();

    return app.exec();
}
