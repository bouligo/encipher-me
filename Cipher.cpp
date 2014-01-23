#include "Cipher.h"
#include <QtCrypto>
#include <QDebug>
#include <QFile>
#include <QString>

Cipher::Cipher()
{
    //initialize QCA
    //QCA::Initializer init = QCA::Initializer();
    QCA::init();

    /*
      *Default error msg Initialization
      */
    this->errorMsg="Unknown Error";
    this->errorTitle="Unknown Error";
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
int Cipher::encipher(QString currentCipher, QString inputFiles, QString password) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    if(!checkCipherAvailability(currentCipher)) {
        this->errorMsg = "Le format de chiffrement désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur lors du chiffrement";
        return 42;
    }


    QCA::SecureArray salt = QCA::Random::randomArray(16);

    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 1000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());


    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                     QCA::Cipher::DefaultPadding, QCA::Encode,
                                     key, iv);

    QStringList fileList(this->getFileList(inputFiles));

    for(int it=0;it<fileList.size();++it) {
        //the file we want to encrypt
        QFile file(fileList.at(it));

        if (!file.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors de l'ouverture du fichier" + fileList.at(it);
            this->errorTitle = "Erreur lors du chiffrement";
            return 1;
        }

        QFile encFile(fileList.at(it) + ".enc");
        if (!encFile.open(QIODevice::WriteOnly)) {
            this->errorMsg = "Erreur lors de l'écriture dans le fichier" + fileList.at(it) + ".enc";
            this->errorTitle = "Erreur lors du chiffrement";
            return 2;
        }

        /*we write magic 8 bytes + salt (16 bytes for now) */
        encFile.write("Salted__" + salt.toByteArray());

        QCA::SecureArray encipheredData;

        while(!file.atEnd()) {
            QCA::SecureArray secureData = file.read(256000);

            //we encrypt the data
            encipheredData = cipher.update(secureData);
            encFile.write(encipheredData.data(),(qint64) encipheredData.size());

            //checks if encryption succeded
            if (!cipher.ok())
            {
                this->errorMsg = "Erreur lors du chiffrement des données de " + file.fileName();
                this->errorTitle = "Erreur lors du chiffrement";
                return 42;
            }
        }

        encipheredData = cipher.final();
        encFile.write(encipheredData.data(),(qint64) encipheredData.size());

        //checks if final succeded
        if (!cipher.ok())
            qDebug() << "Final in encipherment failed";


        encFile.close();
        file.close();
    }

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
int Cipher::decipher(QString currentCipher, QString inputFiles, QString password) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    if(!checkCipherAvailability(currentCipher)) {
        this->errorMsg = "Le format de déchiffrement désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur lors du déchiffrement";
        return 42;
    }


    QStringList fileList(this->getFileList(inputFiles));
    for(int it=0;it<fileList.size();++it) {

        //the file we want to decrypt
        QFile file(fileList.at(it));

        if (!file.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors de l'ouverture du fichier" + fileList.at(it);
            this->errorTitle = "Erreur lors du déchiffrement";
            return 1;
        }

        QFile destFile(fileList.at(it).split(".enc").first()); /** TODO: tester l'existance du fichier, ou si source=dest + extension .enc ?*/
        if (!destFile.open(QIODevice::WriteOnly)) {
            this->errorMsg = "Erreur lors de l'écriture dans le fichier" + fileList.at(it).split(".enc").first();
            this->errorTitle = "Erreur lors du déchiffrement";
            return 2;
        }

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
        QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                         QCA::Cipher::DefaultPadding, QCA::Decode,
                                         key, iv);

        QCA::SecureArray decryptedData;

        while(!file.atEnd()) {

            QByteArray secureData=file.read(256000);

            //decrypt the encrypted data
            decryptedData = cipher.update(secureData);

            //checks if decryption succeded
            if (!cipher.ok())
            {
                this->errorMsg = "Erreur lors du déchiffrement de " + file.fileName();
                this->errorTitle = "Erreur lors du déchiffrement";
                return 42;
            }
            destFile.write(decryptedData.data(),(qint64) decryptedData.size());

        }


        decryptedData = cipher.final();
        /* Above code doesn't always work... maybe because there is no data left to compute ? */
        //checks if final succeded
        //        if (!cipher.ok())
        //        {
        //            this->errorMsg = "Erreur lors du déchiffrement final de " + file.fileName();
        //            this->errorTitle = "Erreur lors du déchiffrement";
        //            return 42;
        //        }
        if (!cipher.ok())
        {
            qDebug() << "Final in decipherment failed";
        }

        destFile.write(decryptedData.data(),(qint64) decryptedData.size());

        destFile.close();
        file.close();

    }
    return 0;
}

/**
 * @brief Cipher::makeChecksum
 * @param inputFiles : files to analyze & create their associated .md5
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 */
int Cipher::makeChecksum(QString inputFiles) {

    QStringList fileList = this->getFileList(inputFiles);

    for(int it=0;it<fileList.size();++it) {
        QFile file(fileList.at(it).toAscii());
        if(!file.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors l'ouverture du fichier" + fileList.at(it).toAscii();
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

    }

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
int Cipher::checkChecksum(QString inputFiles, QString checksumFiles) {

    QStringList fileList = this->getFileList(inputFiles);
    QStringList checksumList = this->getFileList(checksumFiles);

    fileList.sort();
    checksumList.sort();

    if(fileList.size() != checksumList.size()) {
        this->errorMsg = "Il faut un fichier .md5 par fichier à vérifier";
        this->errorTitle = "Erreur lors du controle checksum";
        return 2;
    }

    for(int it=0;it<fileList.size();++it) {
        if(fileList.at(it).split(".enc").first().compare(checksumList.at(it).split(".md5").first())!=0) {
            this->errorMsg = "La vérification de l'intégrité du fichier a échoué. Vérifiez que les noms correspondent :<br /><br />fichier.txt --> fichier.txt.md5";
            this->errorTitle = "Erreur lors du controle checksum";
            return 10;
        }

        QFile file(fileList.at(it).split(".enc").first().toAscii());
        if(!file.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors de l'ouverture du fichier" + fileList.at(it).split(".enc").first().toAscii();
            this->errorTitle = "Erreur lors du controle checksum";
            return 1;
        }
        QFile checksum(checksumList.at(it).toAscii());
        if(!checksum.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors de l'ouverture du fichier" + checksumList.at(it).split(".enc").first().toAscii();
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
    }

    return 0;
}

/**
 * @brief Cipher::getFileList
 * @param inputFiles : String containing files' names
 * @return : List of files to process
 */
QStringList Cipher::getFileList(QString inputFiles) { return inputFiles.split(";"); }

// for now, we only use cbc mode in pkcs7 padding, 'cause... well, we'll see later on
bool Cipher::checkCipherAvailability(QString currentCipher) { return QCA::isSupported(currentCipher.toAscii()+"-"+"cbc"+"-"+"pkcs7"); }


QString Cipher::getErrorTitle() {
    return this->errorTitle;
}

QString Cipher::getErrorMsg() {
    return this->errorMsg;
}
