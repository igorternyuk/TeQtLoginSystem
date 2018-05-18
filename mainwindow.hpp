#ifndef MAINWINDOW_HPP
#define MAINWINDOW_HPP

#include <QMainWindow>
#include "loginDialog.hpp"

namespace Ui
{
    class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(LoginDialog::LoginType loginType,
                        QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_actionUser_database_triggered();

    void on_actionQuit_triggered();

    void on_actionAbout_Qt_triggered();

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_HPP
