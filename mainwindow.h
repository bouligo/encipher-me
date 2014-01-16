#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    void resetUi();

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

private:
    Ui::MainWindow *ui;
};

#endif // MAINWINDOW_H
