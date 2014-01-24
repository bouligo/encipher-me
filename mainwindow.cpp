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
    cipher->show();


    QStringList fileList(this->getFileList(ui->filesToEncipher->text()));

    for(int it=0;it<fileList.size();++it) {

        if(ui->checksumCheckboxToMake->isChecked()) {
            if(cipher->makeChecksum(fileList.at(it))!=0) {
                QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
                delete cipher;
                return;
            }
        }

        if(cipher->encipher(ui->comboBoxCipherToEncipher->currentText(), fileList.at(it), ui->passwordToEncipherWith->text())
                !=0) {
            QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
            delete cipher;
            return;
        }
    }
    QMessageBox::information(this, "Terminé", "Opération de chiffrement du fichier terminée");

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


    QStringList fileList = this->getFileList(ui->filesToDecipher->text());
    QStringList checksumList = this->getFileList(ui->checksumFilesToCheck->text());

    fileList.sort();
    checksumList.sort();

    if(fileList.size() != checksumList.size() && ui->checksumCheckboxToCheck->isChecked()) {
        QMessageBox::critical(this, "Erreur lors du controle checksum", "Il faut un fichier .md5 par fichier à vérifier");
        return;
    }


    Cipher *cipher = new Cipher();
    cipher->show();


    for(int it=0;it<fileList.size();++it) {

        if(cipher->decipher(ui->comboBoxCipherToDecipher->currentText(), fileList.at(it), ui->passwordToDecipherWith->text())!=0)
            QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());


        if(ui->checksumCheckboxToCheck->isChecked()) {
            if(cipher->checkChecksum(fileList.at(it), checksumList.at(it))!=0)
                QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
            else
                QMessageBox::information(this, "Somme de controle", "Vérification du fichier" + fileList.at(it) + "terminée");
        }
    }

    QMessageBox::information(this, "Terminé", "Déchiffrement terminé");
    delete cipher;
}

/**
 * @brief Cipher::getFileList
 * @param inputFiles : String containing files' names
 * @return : List of files to process
 */
QStringList MainWindow::getFileList(QString inputFiles) { return inputFiles.split(";"); }
