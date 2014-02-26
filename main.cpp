/**
 * to check next : decipher /w other ext
 *
 * In current commit : removal of tripledes / md2 (buggy /w my version of qca)
 *                      new extension management
 * quick fix
 *
 * /**
 *  TODO:
 *  Change icon
 * read cipher functions (for names, and sooo on)!!
 * cipher.startOperation : QStringList ?
 *  secured deletion /w abstract inherited class (QString binary = QString::number(QString("0x0").toLongLong(0, 16), 2);)
 *  tooltips à faire
 *  Code factorisation (return code for cipher)
 * better error msg when not compatible
 *  Label progress while checksum-ing :) => nope, new (custom ?)QDialogProgress layout
 *  Make a difference for release/debug (#define, #ifdef)
 *  logfile (x.img enciphered with aes256-cbc at ...
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
