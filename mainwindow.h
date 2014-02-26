#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QProgressDialog>
#include "cipher.h"
#include <QTimer>
#include <QString>
#include <QMessageBox>
#include <QFileDialog>
#include <QFile>
#include <QDebug>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_actionQuitter_triggered();

    void on_actionNouveau_triggered();

    void on_actionAide_triggered();

    void on_actionA_propos_triggered();

    void on_encipher_clicked();

    void on_decipher_clicked();

    void on_browseForFileToEncipher_clicked();

    void on_browseForFileToDecipher_clicked();

    void on_browseForChecksum_clicked();

    void on_checksumCheckboxToCheck_toggled(bool checked);

    void on_checksumCheckboxToMake_clicked(bool checked);


    /** ******************
     * Thread Management *
     ***************** **/
    void startOperation();

    /** *************
     * Custom slots *
     ************* **/

    void setStep(QString text);
    void cancelOperation();

    /** ******
     * Tools *
     ****** **/
    void createDialog(QString text);

    void on_passwordToEncipherWith_returnPressed();

    void on_passwordToDecipherWith_returnPressed();

    void on_expertCheckBox_toggled(bool checked);

private:
    Ui::MainWindow *ui;
    QProgressDialog *dialog;
    QTimer *timer;
    Cipher *cipher;
    QStringList checksumList, encipherList, decipherList, fileList;
    QString currentOperation;
};

#endif // MAINWINDOW_H
