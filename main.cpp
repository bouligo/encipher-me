#include "mainwindow.h"
#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    MainWindow w;
    w.show();

    return a.exec();


}

/**
 *  TODO:
 *  List possible algorithms / modes
 *  thread encipherment
 *  hkep2 ?
 *  large files ? to check
 *  Change icon
 *
 *
 *  -cli alternative
 *  QProgressBar to show status
 */
