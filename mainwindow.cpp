#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    timer = new QTimer();
    timer->setInterval(200);
}

MainWindow::~MainWindow()
{
    timer->deleteLater();
    delete ui;
}

void MainWindow::on_actionNouveau_triggered()
{
    ui->filesToDecipher->setText("");
    ui->filesToEncipher->setText("");
    this->encipherList.empty();
    this->decipherList.empty();

    ui->comboBoxCipherToDecipher->setCurrentIndex(0);
    ui->comboBoxCipherToEncipher->setCurrentIndex(0);

    ui->passwordToDecipherWith->setText("");
    ui->passwordToEncipherWith->setText("");

    ui->checksumCheckboxToCheck->setChecked(false);
    ui->checksumCheckboxToMake->setChecked(false);
    on_checksumCheckboxToMake_clicked(false);
    on_checksumCheckboxToCheck_toggled(false);

    ui->checksumFilesToCheck->setText("");
    this->checksumList.empty();

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
    encipherList = QFileDialog::getOpenFileNames();
    encipherList.sort();
    QString fileString = "";
    for(int i=0;i<encipherList.size();++i)
        fileString += encipherList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->filesToEncipher->setText(fileString);
}

void MainWindow::on_browseForFileToDecipher_clicked()
{
    decipherList = QFileDialog::getOpenFileNames(this, "", "", "Fichiers chiffrés (*.p7);;All (*)");
    decipherList.sort();
    QString fileString = "";
    for(int i=0;i<decipherList.size();++i)
        fileString += decipherList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->filesToDecipher->setText(fileString);
}

void MainWindow::on_browseForChecksum_clicked()
{
    checksumList = QFileDialog::getOpenFileNames(this, "", "", "Fichiers de contrôle (*.md5);;All(*)");
    checksumList.sort();
    QString fileString = "";
    for(int i=0;i<checksumList.size();++i)
        fileString += checksumList.at(i) + ";";
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


void MainWindow::setStep(QString text) { qDebug() << text; dialog->setLabelText(text); }


void MainWindow::cancelOperation() { cipher->stopOperation(); timer->stop(); }


void MainWindow::startOperation() {

    /**
     * First check if previous operation (if any) was successful
     * If not, cancel all planned operation
     */
    if(!cipher->getSuccess())
        currentOperation="";


    /**
     * Current operation is to make a checksum and to encipher
     */
    /// make checksum ...
    if(currentOperation.contains("makeChecksumAndEncipher")) {
        if(!fileList.isEmpty()) {
            cipher->startOperation("makeChecksum", fileList.first());
            fileList.pop_front();
            return;
        }
        fileList=encipherList;
        currentOperation="encipherOnly";
    }
    /// ... and then encipher (or encipher directly)
    if(currentOperation.contains("encipherOnly")) {
        if (!fileList.isEmpty()) {

            cipher->startOperation("encipher", fileList.first(), ui->comboBoxCipherToEncipher->currentText(), ui->passwordToEncipherWith->text());
            fileList.pop_front();
            timer->start();
            return;
        }
        timer->stop();
    }


    /**
     * Current operation is to decipher and maybe to check checksums
     */
    /// Decipher ...
    if(currentOperation.contains("decipher")) {
        if (!fileList.isEmpty()) {

            cipher->startOperation("decipher", fileList.first(), ui->comboBoxCipherToDecipher->currentText(), ui->passwordToDecipherWith->text());
            fileList.pop_front();
            timer->start();
            return;
        }
        timer->stop();
        if(ui->checksumCheckboxToCheck->isChecked()) {
            fileList=checksumList;
            fileList << decipherList;
            currentOperation="checkChecksumOnly";
        }
    }
    /// ... and check checksums files if required
    if(currentOperation.contains("checkChecksumOnly")) {
        if(!fileList.isEmpty()) {
            cipher->startOperation("checkChecksum", fileList.at(fileList.size()/2), "", "", fileList.first());
            fileList.removeAt(fileList.size()/2);
            fileList.pop_front();
            return;
        }
    }


    /**
     * Current operation is to delete files
     */
    ///TODO

    if(cipher->getSuccess())
        QMessageBox::information(this, "terminé", "Opération terminée avec succès !");
    else
        QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());


    dialog->deleteLater();
    cipher->deleteLater();
}


void MainWindow::on_encipher_clicked() {

    if(ui->filesToEncipher->text().isEmpty() || ui->passwordToEncipherWith->text().isEmpty()) {
        QMessageBox::warning(this, "Fichier/mot de passe requis", "Il faut indiquer un fichier à chiffrer et un mot de passe.");
        return;
    }

    cipher = new Cipher();

    createDialog("Chiffrement");

    connect(cipher, SIGNAL(stepChanged(QString)), this, SLOT(setStep(QString)));
    connect(cipher, SIGNAL(finished()), this, SLOT(startOperation()));
    connect(cipher, SIGNAL(progressionChanged(int)), dialog, SLOT(setValue(int)));
    connect(dialog, SIGNAL(canceled()), this, SLOT(cancelOperation()));
    connect(timer, SIGNAL(timeout()), cipher, SLOT(emitProgression()));

    fileList=encipherList;

    if(ui->checksumCheckboxToMake->isChecked())
        currentOperation="makeChecksumAndEncipher";
    else
        currentOperation="encipherOnly";

    this->startOperation();

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
    if(decipherList.size() != checksumList.size() && ui->checksumCheckboxToCheck->isChecked()) {
        QMessageBox::critical(this, "Erreur lors du controle checksum", "Il faut un fichier .md5 par fichier à vérifier");
        return;
    }

    cipher = new Cipher();

    createDialog("Déchiffrement");

    connect(cipher, SIGNAL(stepChanged(QString)), this, SLOT(setStep(QString)));
    connect(cipher, SIGNAL(finished()), this, SLOT(startOperation()));
    connect(cipher, SIGNAL(progressionChanged(int)), dialog, SLOT(setValue(int)));
    connect(dialog, SIGNAL(canceled()), this, SLOT(cancelOperation()));
    connect(timer, SIGNAL(timeout()), cipher, SLOT(emitProgression()));

    fileList=decipherList;

    currentOperation="decipher";

    this->startOperation();

}


void MainWindow::createDialog(QString text) {
    dialog = new QProgressDialog(text, "Annuler", 0, 100, this);
    dialog->setModal(true);
    dialog->setFixedSize(600,100);
    dialog->show();
    dialog->setValue(0);
}

void MainWindow::on_passwordToEncipherWith_returnPressed()
{
    this->on_encipher_clicked();
}

void MainWindow::on_passwordToDecipherWith_returnPressed()
{
    this->on_decipher_clicked();
}
