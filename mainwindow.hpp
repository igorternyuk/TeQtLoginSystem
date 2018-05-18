#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include "dbmanager.hpp"
#include "loginDialog.hpp"

namespace Ui
{
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(DbManager& manager,
                        LoginDialog::LoginType loginType =
                         LoginDialog::LoginType::RegularUser,
                        QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_actionUser_database_triggered();
    void on_actionQuit_triggered();
    void on_actionAbout_Qt_triggered();

private:
    Ui::MainWindow *ui;
    DbManager& mDbManager;
};

#endif // MAINWINDOW_HPP
