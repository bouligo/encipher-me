#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "Cipher.h"
#include <QMessageBox>
#include <QFileDialog>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::resetUi() {

    /** empty other text fields */
}

void MainWindow::on_actionNouveau_triggered()
{
    this->resetUi();
}

void MainWindow::on_actionQuitter_triggered()
{
    QApplication::exit();
}

void MainWindow::on_actionAide_triggered()
{
    QMessageBox::information(this, "Aide", "Aide à afficher");
}

void MainWindow::on_actionA_propos_triggered()
{
    QMessageBox::information(this, "À propos", "Crédits");
}

void MainWindow::on_browseForFileToEncipher_clicked()
{
    QStringList fileList = QFileDialog::getOpenFileNames();
    QString fileString = "";
    for(int i=0;i<fileList.size();++i)
        fileString += fileList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->filesToEncipher->setText(fileString);
}

void MainWindow::on_browseForFileToDecipher_clicked()
{
    QStringList fileList = QFileDialog::getOpenFileNames();
    QString fileString = "";
    for(int i=0;i<fileList.size();++i)
        fileString += fileList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->filesToDecipher->setText(fileString);
}

void MainWindow::on_browseForChecksum_clicked()
{
    QStringList fileList = QFileDialog::getOpenFileNames();
    QString fileString = "";
    for(int i=0;i<fileList.size();++i)
        fileString += fileList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->checksumFilesToCheck->setText(fileString);
}

void MainWindow::on_checksumCheckboxToCheck_toggled(bool checked)
{
    ui->browseForChecksum->setEnabled(checked);
    ui->checksumFilesToCheck->setEnabled(checked);
}

void MainWindow::on_checksumCheckboxToMake_clicked(bool checked)
{
    if(checked) {
        ui->checksumCreationState->setText("Création d'un fichier checksum");
        ui->checksumCreationState->setStyleSheet("color:green");
    }
    else {
        ui->checksumCreationState->setText("Pas de somme de hashage");
        ui->checksumCreationState->setStyleSheet("color:red");
    }
}

void MainWindow::on_encipher_clicked()
{
    if(ui->filesToEncipher->text().isEmpty() || ui->passwordToEncipherWith->text().isEmpty()) {
        QMessageBox::warning(this, "Fichier/mot de passe requis", "Il faut indiquer un fichier à chiffrer et un mot de passe.");
        return;
    }
    Cipher *cipher = new Cipher();

    if(ui->checksumCheckboxToMake->isChecked()) {
        if(cipher->makeChecksum(ui->filesToEncipher->text())!=0) {
            QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
            delete cipher;
            return;
        }
    }

    if(cipher->encipher(ui->comboBoxCipherToEncipher->currentText(), ui->filesToEncipher->text(), ui->passwordToEncipherWith->text())
            ==0)
        QMessageBox::information(this, "Terminé", "Opération de chiffrement du fichier terminée");
    else
        QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
    delete cipher;
}

void MainWindow::on_decipher_clicked()
{
    if(ui->filesToDecipher->text().isEmpty() || ui->passwordToDecipherWith->text().isEmpty()) {
        QMessageBox::warning(this, "Fichier/mot de passe requis", "Il faut indiquer un fichier à déchiffrer et un mot de passe.");
        return;
    }
    if(ui->checksumCheckboxToCheck->isChecked() && ui->checksumFilesToCheck->text().isEmpty()) {
        QMessageBox::warning(this, "Fichier hash requis", "Il faut indiquer un fichier de somme de hashage.");
        return;
    }

    Cipher *cipher = new Cipher();


    if(!cipher->decipher(ui->comboBoxCipherToDecipher->currentText(), ui->filesToDecipher->text(), ui->passwordToDecipherWith->text()))
        QMessageBox::information(this, "Terminé", "Opération de déchiffrement du fichier terminée");
    else {
        QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
        return;
    }

    if(ui->checksumCheckboxToCheck->isChecked()) {

        if(cipher->checkChecksum(ui->filesToDecipher->text(), ui->checksumFilesToCheck->text())==0)
            QMessageBox::information(this, "Somme de controle", "Vérification du fichier final terminée");
        else
            QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
    }

    delete cipher;
}
