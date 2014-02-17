/**
 *  TODO:
 *  List possible algorithms / modes
 *  Change icon
 *  secured deletion /w abstract inherited class
 *  Code factorisation
 *  Label progress while checksum-ing :)
 *  Make a difference for release/debug (#define, #ifdef)
 *  logfile (x.img enciphered with aes256-cbc at ...
 *  start operation when pressing enter
 *  Emit warning when a file will be overwritten (and make open/closeFile function)
 *
 *  -cli alternative
 */


#include "mainwindow.h"
#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    MainWindow w;
    w.show();

    return a.exec();


}
