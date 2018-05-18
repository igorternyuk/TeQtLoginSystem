#include "dbmanager.hpp"
#include "loginDialog.hpp"
#include "mainwindow.hpp"
#include <QApplication>
#include <QDesktopWidget>
#include <QDebug>
#include <stdexcept>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    DbManager manager;
    try
    {
        manager.createDatabase();
        manager.configureDatabase();
    }
    catch(std::exception &ex)
    {
        qCritical() << ex.what();
    }

    app.setStyle("fusion");

    LoginDialog loginDialog(manager);
    if(loginDialog.exec() == LoginDialog::Rejected)
    {
        return 0;
    }

    MainWindow window(manager, loginDialog.getLoginType());
    window.move(QApplication::desktop()->rect().center() - window.rect().center());
    window.show();
    return app.exec();
}
