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


    QCA::SecureArray salt = QCA::Random::randomArray(16);

    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 1000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());


    qDebug() << "Password: " + password << ", salt: " << salt.toByteArray() << ", key: " << key.toByteArray() << ", iv: " << iv.toByteArray() << ", hash: " << iv.toByteArray() << iv.size();

    //    if(!checkCipherAvailability(currentCipher))
    //        return 42;

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

        QCA::SecureArray secureData = file.readAll();
        file.close();


        //we encrypt the data
        QCA::SecureArray encipheredData = cipher.process(secureData);

        //checks if encryption succeded
        if (!cipher.ok())
        {
            this->errorMsg = "Erreur lors du chiffrement des données de " + file.fileName();
            this->errorTitle = "Erreur lors du chiffrement";
            return 42;
        }

        QFile encFile(fileList.at(it) + ".enc");
        if (!encFile.open(QIODevice::WriteOnly)) {
            this->errorMsg = "Erreur lors de l'écriture dans le fichier" + fileList.at(it) + ".enc";
            this->errorTitle = "Erreur lors du chiffrement";
            return 2;
        }

        /*we write magic 8 bytes + salt (16 bytes for now) */
        encFile.write("Salted__" + salt.toByteArray());

        encFile.write(encipheredData.data(),(qint64) encipheredData.size());
        encFile.close();
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

    QStringList fileList(this->getFileList(inputFiles));
    for(int it=0;it<fileList.size();++it) {

        //the file we want to decrypt
        QFile file(fileList.at(it));

        if (!file.open(QIODevice::ReadOnly)) {
            this->errorMsg = "Erreur lors de l'ouverture du fichier" + fileList.at(it);
            this->errorTitle = "Erreur lors du déchiffrement";
            return 1;
        }


        QCA::SecureArray fileContent = file.readAll();
        file.close();

        QString saltQString = fileContent.toByteArray();
        saltQString.truncate(24);
        saltQString.remove(0,8);
        QCA::SecureArray salt = saltQString.toAscii(); /* salt pas bon ? */

        QByteArray secureData = fileContent.toByteArray().remove(0,24);


        QCA::PBKDF2 pbkdf2;
        QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 1000); //100K or more

        QCA::Hash hash("md5");
        hash.update(key.toByteArray());
        QCA::InitializationVector iv = QCA::SecureArray(hash.final());

        qDebug() << "Password: " + password << ", salt: " << salt.toByteArray() << ", key: " << key.toByteArray() << ", iv: " << iv.toByteArray() << ", hash: " << iv.toByteArray() << iv.size();

        //    if(!checkCipherAvailability(currentCipher))
        //        return 42;

        /*
         * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
         */
        QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                         QCA::Cipher::DefaultPadding, QCA::Decode,
                                         key, iv);

        //decrypt the encrypted data
        QCA::SecureArray decryptedData = cipher.process(secureData);

        //checks if decryption succeded
        if (!cipher.ok())
        {
            this->errorMsg = "Erreur lors du déchiffrement de " + file.fileName();
            this->errorTitle = "Erreur lors du déchiffrement";
            return 42;
        }


        QFile destFile(fileList.at(it).split(".enc").first()); /** TODO: tester l'existance du fichier, ou si source=dest + extension .enc ?*/
        if (!destFile.open(QIODevice::WriteOnly)) {
            this->errorMsg = "Erreur lors de l'écriture dans le fichier" + fileList.at(it).split(".enc").first();
            this->errorTitle = "Erreur lors du déchiffrement";
            return 2;
        }

        destFile.write(decryptedData.data(),(qint64) decryptedData.size());
        destFile.close();


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

//bool Cipher::checkCipherAvailability(QString currentCipher) {
//    return QCA::isSupported(currentCipher.toAscii()); //TO FIX
//}


QString Cipher::getErrorTitle() {
    return this->errorTitle;
}

QString Cipher::getErrorMsg() {
    return this->errorMsg;
}
