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

void MainWindow::on_expertCheckBox_toggled(bool checked)
{
    ui->expert_comboBoxCipherMode->setEnabled(checked);
    ui->expert_comboBoxHashAlgorithm->setEnabled(checked);
    ui->expert_comboBoxPadding->setEnabled(checked);
    if(!checked) {
        ui->expert_comboBoxCipherMode->setCurrentIndex(1);
        ui->expert_comboBoxHashAlgorithm->setCurrentIndex(2);
        ui->expert_comboBoxPadding->setCurrentIndex(1);
    }
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
    decipherList = QFileDialog::getOpenFileNames(this, "", "", "Fichiers chiffrés *." + ui->comboBoxCipherToDecipher->currentText() + (ui->expert_comboBoxPadding->currentText().isEmpty() ? "" : ".p7") + "(*." + ui->comboBoxCipherToDecipher->currentText() + (ui->expert_comboBoxPadding->currentText().isEmpty() ? "" : ".p7") + ");;All (*)");
    decipherList.sort();
    QString fileString = "";
    for(int i=0;i<decipherList.size();++i)
        fileString += decipherList.at(i) + ";";
    fileString.remove(fileString.size()-1,1);
    ui->filesToDecipher->setText(fileString);
}

void MainWindow::on_browseForChecksum_clicked()
{
    checksumList = QFileDialog::getOpenFileNames(this, "", "", "Fichiers de contrôle " + ui->expert_comboBoxHashAlgorithm->currentText() + " (*." + ui->expert_comboBoxHashAlgorithm->currentText() +");;All(*)");
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


void MainWindow::on_passwordToEncipherWith_returnPressed()
{
    this->on_encipher_clicked();
}

void MainWindow::on_encipher_clicked() {

    if(ui->filesToEncipher->text().isEmpty() || ui->passwordToEncipherWith->text().isEmpty()) {
        QMessageBox::warning(this, "Fichier/mot de passe requis", "Il faut indiquer un fichier à chiffrer et un mot de passe.");
        return;
    }


    fileList=encipherList;

    for(int i=0;i<this->fileList.size();++i) {
        QString futureFileName=this->fileList.at(i).toAscii()+"."+ui->comboBoxCipherToEncipher->currentText().toAscii()+(ui->expert_comboBoxPadding->currentText()=="" ? "" : ".p7");
        if(QFile::exists(futureFileName))
            if(QMessageBox::No==QMessageBox::question(this, "Ecraser ?", "Le fichier " + futureFileName + " existe déjà. Voulez vous l'écraser ?", QMessageBox::Yes|QMessageBox::No))
                this->fileList.replace(i,QFileDialog::getOpenFileName());
    }

    cipher = new Cipher();

    createDialog("Chiffrement");
    dialog->setTotalNumberOfFiles(fileList.size());

    connect(cipher, SIGNAL(stepChanged(QString)), this, SLOT(setStep(QString)));
    connect(cipher, SIGNAL(finished()), this, SLOT(startOperation()));
    connect(cipher, SIGNAL(progressionChanged(int)), dialog, SLOT(setCurrentProgression(int)));
    connect(dialog, SIGNAL(canceled()), this, SLOT(cancelOperation()));
    connect(timer, SIGNAL(timeout()), cipher, SLOT(emitProgression()));

    if(ui->checksumCheckboxToMake->isChecked())
        currentOperation="makeChecksumAndEncipher";
    else
        currentOperation="encipherOnly";

    this->startOperation();

}

void MainWindow::on_passwordToDecipherWith_returnPressed()
{
    this->on_decipher_clicked();
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
        QMessageBox::critical(this, "Erreur lors du controle checksum", "Il faut un fichier de controle par fichier à vérifier");
        return;
    }

    fileList=decipherList;

    for(int i=0;i<this->fileList.size();++i) {
        QString futureFileName = this->fileList.at(i);
        if(futureFileName.endsWith(".p7"))
            futureFileName.remove(futureFileName.length()-3,3);
        if(futureFileName.endsWith(".aes128")
                ||futureFileName.endsWith(".aes192")
                ||futureFileName.endsWith(".aes256"))
            futureFileName.remove(futureFileName.length()-7,7);
        else if(futureFileName.endsWith(".blowfish"))
            futureFileName.remove(futureFileName.length()-9,9);
        else if(futureFileName.endsWith(".des"))
            futureFileName.remove(futureFileName.length()-4,4);
        else if(futureFileName.endsWith(".cast5"))
            futureFileName.remove(futureFileName.length()-6,6);

        if(QFile::exists(futureFileName))
            if(QMessageBox::No==QMessageBox::question(this, "Ecraser ?", "Le fichier " + futureFileName + " existe déjà. Voulez vous l'écraser ?", QMessageBox::Yes|QMessageBox::No))
                this->fileList.replace(i,QFileDialog::getOpenFileName());
            else
                fileList.replace(i, futureFileName);
        else
            fileList.replace(i, futureFileName);
    }

    fileList << decipherList;

    cipher = new Cipher();

    createDialog("Déchiffrement");
    dialog->setTotalNumberOfFiles(fileList.size()/2);

    connect(cipher, SIGNAL(stepChanged(QString)), this, SLOT(setStep(QString)));
    connect(cipher, SIGNAL(finished()), this, SLOT(startOperation()));
    connect(cipher, SIGNAL(progressionChanged(int)), dialog, SLOT(setCurrentProgression(int)));
    connect(dialog, SIGNAL(canceled()), this, SLOT(cancelOperation()));
    connect(timer, SIGNAL(timeout()), cipher, SLOT(emitProgression()));

    currentOperation="decipher";

    this->startOperation();

}

/**
 * @brief MainWindow::create : Create QProgressDialog /w custom params
 * @param text : initial text to display
 */
void MainWindow::createDialog(QString text) {
    //    dialog = new QProgressDialog(text, "Annuler", 0, 100, this);
    //    dialog->setModal(true);


    dialog = new Progression(text);
    dialog->show();
}

/**
 * @brief MainWindow::setStep : changes to text in the dialog box
 * @param text : text to display
 */
void MainWindow::setStep(QString text) { qDebug() << text; dialog->setLabelText(text); }

/**
 * @brief MainWindow::cancelOperation : stop current operation
 */
void MainWindow::cancelOperation() { cipher->stopOperation(); timer->stop(); }

/**
 * @brief MainWindow::startOperation : starts cipher operation, through this.currentOperation
 */
void MainWindow::startOperation() {

    //disable application, to prevent user to start another thread
    ui->centralWidget->setEnabled(false);

    /**
     * First check if previous operation (if any) was successful
     * If not, cancel all planned operation
     * If error while doing operation on checksums, continue
     */
    if(!cipher->getSuccess() && currentOperation.contains("Checksum"))
        QMessageBox::warning(this, cipher->getErrorTitle(), cipher->getErrorMsg());
    else if(!cipher->getSuccess())
        QMessageBox::critical(this, cipher->getErrorTitle(), cipher->getErrorMsg());
    if(cipher->getCanceled())
        currentOperation="";

    /**
     * Update 2nd QProgressBar
     */
    if(currentOperation.contains("makeChecksumAndEncipher")
            ||currentOperation.contains("encipherOnly"))
        dialog->setCurrentNumberOfFiles(encipherList.size() - fileList.size());
    else
        dialog->setCurrentNumberOfFiles(decipherList.size() - (fileList.size()/2));

    /**
     * Current operation is to make a checksum and to encipher
     */
    /// make checksum ...
    if(currentOperation.contains("makeChecksumAndEncipher")) {
        if(!fileList.isEmpty()) {
            cipher->startOperation("makeChecksum", fileList.first(), fileList.first()+"."+ui->expert_comboBoxHashAlgorithm->currentText(), ui->expert_comboBoxHashAlgorithm->currentText());
            fileList.pop_front();
            return;
        }
        fileList=encipherList;
        dialog->setCurrentNumberOfFiles(encipherList.size() - fileList.size());
        currentOperation="encipherOnly";

    }
    /// ... and then encipher (or encipher directly)
    if(currentOperation.contains("encipherOnly")) {
        if (!fileList.isEmpty()) {
            cipher->startOperation("encipher", fileList.first(), fileList.first()+"."+ui->comboBoxCipherToEncipher->currentText().toAscii()+(ui->expert_comboBoxPadding->currentText()=="" ? "" : ".p7"), ui->comboBoxCipherToEncipher->currentText(), ui->passwordToEncipherWith->text(), "", ui->expert_comboBoxPadding->currentText(), ui->expert_comboBoxCipherMode->currentText());
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
            bool result = cipher->startOperation("decipher", fileList.at(fileList.size()/2), fileList.first(), ui->comboBoxCipherToDecipher->currentText(), ui->passwordToDecipherWith->text(), "", ui->expert_comboBoxPadding->currentText(), ui->expert_comboBoxCipherMode->currentText());
            fileList.removeAt(fileList.size()/2);
            fileList.pop_front();

            if(!result)
                this->startOperation();
            else
                timer->start();

            return;
        }
        timer->stop();
        if(ui->checksumCheckboxToCheck->isChecked()) {
            fileList=checksumList;
            fileList << decipherList;
            dialog->setCurrentNumberOfFiles(encipherList.size() - (fileList.size()/2));
            currentOperation="checkChecksumOnly";
        }
    }
    /// ... and check checksums files if required
    if(currentOperation.contains("checkChecksumOnly")) {
        if(!fileList.isEmpty()) {
            cipher->startOperation("checkChecksum", fileList.at(fileList.size()/2).split("."+ui->comboBoxCipherToDecipher->currentText()+(ui->expert_comboBoxPadding->currentText().isEmpty() ? "" : ".p7")).first(), "", ui->expert_comboBoxHashAlgorithm->currentText(), "", fileList.first());
            fileList.removeAt(fileList.size()/2);
            fileList.pop_front();
            return;
        }
    }


    /**
     * Current operation is to delete files
     */
    ///TODO

    if(cipher->getCanceled())
        QMessageBox::critical(this, "Annulé", "Opération annulée");
    else
        QMessageBox::information(this, "terminé", "Opération terminée");

    //re-enables application
    ui->centralWidget->setEnabled(true);

    dialog->deleteLater();
    cipher->deleteLater();
}
