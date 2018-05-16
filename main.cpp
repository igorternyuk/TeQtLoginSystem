#include "dialog.hpp"
#include <QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setStyle("fusion");
    Dialog w;
    w.show();

    return app.exec();
}
