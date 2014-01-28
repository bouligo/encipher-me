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
 *  large files ? to check
 *  Change icon
 *  filter on extentions in file explorer
 *  change md5 for hashing key
 *  expert mode
 *
 *
 *  -cli alternative
 *  QProgressBar to show status
 */
