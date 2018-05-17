#ifndef DIALOG_HPP
#define DIALOG_HPP

#include <QDialog>

namespace Ui
{
    class Dialog;
}

class Dialog : public QDialog
{
    Q_OBJECT

public:
    explicit Dialog(QWidget *parent = nullptr);
    ~Dialog();

private slots:
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();
    void on_btnRegisterAdmin_clicked();

private:
    enum class LoginType
    {
        RegularUser,
        Administrator
    };
    Ui::Dialog *ui;
    void checkIfAdminExists();
};

#endif // DIALOG_HPP
