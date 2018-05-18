#include "mainwindow.hpp"
#include "ui_mainwindow.h"
#include "usermanagmentform.hpp"
#include <QMdiSubWindow>
#include <QMessageBox>

MainWindow::MainWindow(LoginDialog::LoginType loginType, QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    if(loginType == LoginDialog::LoginType::Administrator)
    {
        ui->actionUser_database->setEnabled(true);
    }
    else
    {
        ui->actionUser_database->setEnabled(false);
    }
    this->setCentralWidget(ui->mdiArea);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_actionUser_database_triggered()
{
    UserManagmentForm *form = new UserManagmentForm(this);
    auto subWindow = ui->mdiArea->addSubWindow(form);
    subWindow->setGeometry(form->geometry());
    subWindow->setWindowTitle(form->windowTitle());
    subWindow->show();
}

void MainWindow::on_actionQuit_triggered()
{
    int reply = QMessageBox::question(this, "Confirm exit, please",
                          "Do you really want to exit program?",
                          QMessageBox::Yes | QMessageBox::No);
    if(reply == QMessageBox::Yes)
    {
        this->close();
        //qApp->quit();
    }
}

void MainWindow::on_actionAbout_Qt_triggered()
{
    QMessageBox::aboutQt(this, "About Qt");
}
