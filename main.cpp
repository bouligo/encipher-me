/**
 *
 *
 * /**
 *  TODO:
 * add "yes to all" for overwrite
 *  1/1 "fichiers" + hide 0% when checksum-ing
 *  Change icon
 * cipher.startOperation : QStringList ?
 *  secured deletion /w abstract inherited class (QString binary = QString::number(QString("0x0").toLongLong(0, 16), 2);)
 *  tooltips à faire // needed for release
 *  Code factorisation (return code for cipher)
 * better error msg when not compatible
 *  Make a difference for release/debug (#define, #ifdef)
 *  logfile (x.img enciphered with aes256-cbc at ...
 * suppress MainWindow::setStep ?
 *
 *  -cli alternative
 */


#include "mainwindow.h"
#include <QApplication>


int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    if(argc>1) {
        /**
         * working through CLI
         */
    } else {
        MainWindow w;
        w.show();
        return a.exec();
    }
}
