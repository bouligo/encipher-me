#include "ui_cipher.h"
#include "Cipher.h"
#include <QtCrypto>
#include <QDebug>
#include <QFile>
#include <QString>

Cipher::Cipher(QWidget *parent) :
    QWidget(parent),
    ui(new Ui::Cipher)
{
    ui->setupUi(this);

    //initialize QCA
    //QCA::Initializer init = QCA::Initializer();
    QCA::init();

    /*
     * Default error msg Initialization
     */
    this->errorMsg="Unknown Error";
    this->errorTitle="Unknown Error";
}

Cipher::~Cipher()
{
    delete ui;
}


/**
 * @brief Cipher::encipher : encipher a list of file with a single password
 * @param currentCipher : cipher to use
 * @param inputFiles : list of files to encipher
 * @param password : password to use
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 * @return 42 : encipherment failed
 */
int Cipher::encipher(QString currentCipher, QString inputFile, QString password) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    ui->step->setText("Vérification des pré-requis");
    if(!checkCipherAvailability(currentCipher)) {
        ui->step->setText("Erreur");
        this->errorMsg = "Le format de chiffrement désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur lors du chiffrement";
        return 42;
    }

    ui->step->setText("Calcul de la clé privée & autres pré-requis");
    QCA::SecureArray salt = QCA::Random::randomArray(16);

    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 1000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());


    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    ui->step->setText("Configuration du chiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                     QCA::Cipher::PKCS7, QCA::Encode,
                                     key, iv);





    //the file we want to encrypt
    QFile file(inputFile);
    ui->step->setText("Ouverture"); //  todo: filename sans chemin
    if (!file.open(QIODevice::ReadOnly)) {
        ui->step->setText("Erreur lors de l'ouverture de " + file.fileName());
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + file.fileName();
        this->errorTitle = "Erreur lors du chiffrement";
        return 1;
    }

    ui->step->setText("Ouverture de " + file.fileName());
    QFile encFile(inputFile + ".enc");
    if (!encFile.open(QIODevice::WriteOnly)) {
        ui->step->setText("Erreur lors de l'écriture");
        this->errorMsg = "Erreur lors de l'écriture dans le fichier" + encFile.fileName() + ".enc";
        this->errorTitle = "Erreur lors du chiffrement";
        return 2;
    }

    ui->step->setText("Chiffrement");
    /*we write magic 8 bytes + salt (16 bytes for now) */
    encFile.write("Salted__" + salt.toByteArray());

    QCA::SecureArray encipheredData;

    while(!file.atEnd()) {
        QCA::SecureArray secureData = file.read(256000);
        ui->progressBar->setValue((int) ((file.pos()*100)/file.size()));
        //we encrypt the data
        encipheredData = cipher.update(secureData);

        //checks if encryption succeded
        if (!cipher.ok())
        {
            ui->step->setText(">Erreur lors du chiffrement");
            this->errorMsg = "Erreur lors du chiffrement des données de " + file.fileName();
            this->errorTitle = "Erreur lors du chiffrement";
            return 42;
        }

        encFile.write(encipheredData.data(),(qint64) encipheredData.size());
    }

    encipheredData = cipher.final();
    encFile.write(encipheredData.data(),(qint64) encipheredData.size());

    //checks if final succeded
    if (!cipher.ok())
    {
        this->errorMsg = "Erreur lors du padding des données de " + file.fileName();
        this->errorTitle = "Erreur lors du padding";
        return 42;
    }


    encFile.close();
    file.close();


    return 0;

}

/**
 * @brief Cipher::decipher : decipher a list of file with a single password
 * @param currentCipher : cipher to use
 * @param inputFiles : list of files to decipher
 * @param password : password to use
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 * @return 42 : decipherment failed
 */
int Cipher::decipher(QString currentCipher, QString inputFile, QString password) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    ui->step->setText("Vérification des pré-requis");
    if(!checkCipherAvailability(currentCipher)) {
        ui->step->setText("Erreur");
        this->errorMsg = "Le format de déchiffrement désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur lors du déchiffrement";
        return 42;
    }


    //the file we want to decrypt
    QFile file(inputFile);
    ui->step->setText("Ouverture de " + file.fileName());
    if (!file.open(QIODevice::ReadOnly)) {
        ui->step->setText("Erreur lors de l'ouverture de " + file.fileName());
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + file.fileName();
        this->errorTitle = "Erreur lors du déchiffrement";
        return 1;
    }

    QFile destFile(inputFile.split(".enc").first()); /** TODO: tester l'existance du fichier, ou si source=dest + extension .enc ?*/
    ui->step->setText("Écriture de " + destFile.fileName());
    if (!destFile.open(QIODevice::WriteOnly)) {
        ui->step->setText("Erreur lors de l'écriture de " + destFile.fileName());
        this->errorMsg = "Erreur lors de l'écriture dans le fichier" + inputFile.split(".enc").first();
        this->errorTitle = "Erreur lors du déchiffrement";
        return 2;
    }

    ui->step->setText("Calcul de la clé privée & autres pré-requis");

    file.read(8); //ignore first 8 bytes
    QCA::SecureArray salt = file.read(16);


    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 1000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());

    /*
         * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
         */
    ui->step->setText("Configuration du déchiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                     QCA::Cipher::PKCS7, QCA::Decode,
                                     key, iv);

    QCA::SecureArray decryptedData;

    ui->step->setText("Déchiffrement de " + file.fileName());
    while(!file.atEnd()) {

        QByteArray secureData=file.read(256000);
        ui->progressBar->setValue((int) ((file.pos()*100)/file.size()));
        //decrypt the encrypted data
        decryptedData = cipher.update(secureData);

        //checks if decryption succeded
        if (!cipher.ok())
        {
            ui->step->setText("Erreur lors du déchiffrement de " + file.fileName());
            this->errorMsg = "Erreur lors du déchiffrement de " + file.fileName();
            this->errorTitle = "Erreur lors du déchiffrement";
            return 42;
        }
        destFile.write(decryptedData.data(),(qint64) decryptedData.size());

    }


    decryptedData = cipher.final();

    /* Above code doesn't always work... maybe because there is no data left to compute ? */
    //checks if final succeded
    if (!cipher.ok())
    {
        this->errorMsg = "Erreur lors du déchiffrement final de " + file.fileName();
        this->errorTitle = "Erreur lors du déchiffrement";
        return 42;
    }

    destFile.write(decryptedData.data(),(qint64) decryptedData.size());

    destFile.close();
    file.close();


    return 0;
}

/**
 * @brief Cipher::makeChecksum
 * @param inputFiles : files to analyze & create their associated .md5
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 */
int Cipher::makeChecksum(QString inputFile) {

    ui->progressBar->setValue(-1);

    QFile file(inputFile.toAscii());
    if(!file.open(QIODevice::ReadOnly)) {
        this->errorMsg = "Erreur lors l'ouverture du fichier" + inputFile.toAscii();
        this->errorTitle = "Erreur lors du controle checksum";
        return 1;
    }
    QCA::Hash hash("md5");
    hash.update(&file);
    QString md5hash = hash.final().toByteArray().toHex();
    file.close();

    /* TODO: check errors ? */

    QFile destFile(file.fileName() + ".md5");
    if(!destFile.open(QIODevice::WriteOnly)) {
        this->errorMsg = "Erreur lors de la création du fichier" + file.fileName() + ".md5";
        this->errorTitle = "Erreur lors du controle checksum";
        return 2;
    }
    destFile.write(md5hash.toAscii(), (quint64) md5hash.size());
    destFile.close();


    return 0;
}

/**
 * @brief Cipher::checkChecksum : check a list of .md5 with their associated files
 * @param inputFiles : files to check
 * @param checksumFiles : .md5 to compare
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : incorrect number of *.md5 provided
 * @return 10 : names between files and .md5 differ
 * @return 42 : md5 check fails
 */
int Cipher::checkChecksum(QString inputFile, QString checksumFile) {

    if(inputFile.split(".enc").first().compare(checksumFile.split(".md5").first())!=0) {
        this->errorMsg = "La vérification de l'intégrité du fichier a échoué. Vérifiez que les noms correspondent :<br /><br />fichier.txt --> fichier.txt.md5";
        this->errorTitle = "Erreur lors du controle checksum";
        return 10;
    }

    QFile file(inputFile.split(".enc").first().toAscii());
    if(!file.open(QIODevice::ReadOnly)) {
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + inputFile.split(".enc").first().toAscii();
        this->errorTitle = "Erreur lors du controle checksum";
        return 1;
    }
    QFile checksum(checksumFile.toAscii());
    if(!checksum.open(QIODevice::ReadOnly)) {
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + checksumFile.split(".enc").first().toAscii();
        this->errorTitle = "Erreur lors du controle checksum";
        return 1;
    }
    QString contentOfChecksumFile = checksum.readAll();
    contentOfChecksumFile=contentOfChecksumFile.split("\n").first();

    QCA::Hash hash("md5");
    hash.update(&file);
    QString md5hash = hash.final().toByteArray().toHex();
    file.close();
    checksum.close();

    if(contentOfChecksumFile.compare(md5hash) != 0) {
        this->errorMsg = "Les fichiers<br />" + file.fileName() + "<br />et<br />" + checksum.fileName() + "<br />ne correspondent pas";
        this->errorTitle = "Erreur lors du controle checksum";
        return 42;
    }


    return 0;
}

// for now, we only use cbc mode in pkcs7 padding, 'cause... well, we'll see later on
bool Cipher::checkCipherAvailability(QString currentCipher) { return QCA::isSupported(currentCipher.toAscii()+"-"+"cbc"+"-"+"pkcs7"); }


QString Cipher::getErrorTitle() {
    return this->errorTitle;
}

QString Cipher::getErrorMsg() {
    return this->errorMsg;
}
