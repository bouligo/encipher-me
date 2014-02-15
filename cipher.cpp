#include "cipher.h"

Cipher::Cipher()
{
    //initialize QCA
    //QCA::Initializer init = QCA::Initializer();
    QCA::init();

    /*
     * Default error msg Initialization
     */
    this->errorMsg="Unknown Error";
    this->errorTitle="Unknown Error";
    this->success=true;
    this->canceled=false;
}

/**
 * @brief Cipher::startOperation : main entry point for other classes
 * @param newOperation : can be encipher, decipher, ...
 * @param inputFile : the file to process
 * @param currentCipher : algorithm to use
 * @param pass : password
 * @param checksum : checksum file (if newOperation.equals(checkChecksum)
 */
void Cipher::startOperation(QString newOperation, QString inputFile, QString currentCipher, QString pass, QString checksum) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    emit stepChanged("Vérification des pré-requis");

    //(!currentCipher.isEmpty()) because of (check/make)Checksum
    if(!currentCipher.isEmpty() && !checkCipherAvailability(currentCipher)) {
        emit stepChanged("Erreur");
        this->errorMsg = "L'algorithme désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur";
        this->success=false;
        emit finished();
        return;
    }


    this->operation = newOperation;
    this->algo = currentCipher;
    this->in = new QFile(inputFile);
    this->password = pass;
    this->checksum = new QFile(checksum);

    this->start();
}

/**
 * @brief Cipher::run : inherited by QThread
 */
void Cipher::run() {
    if(this->operation.contains("encipher"))
        this->encipher(this->algo, this->password);
    if(this->operation.contains("decipher"))
        this->decipher(this->algo, this->password);
    if(this->operation.contains("makeChecksum"))
        this->makeChecksum();
    if(this->operation.contains("checkChecksum"))
        this->checkChecksum();
}


/** ***************
 * Tools & slots  *
 ************** **/


// for now, we only use cbc mode in pkcs7 padding, 'cause... well, we'll see later on
/**
 * can theoricaly be ("aes128-ecb", "aes128-cfb", "aes128-cbc", "aes128-cbc-pkcs7", "aes128-ofb",
 * "aes192-ecb", "aes192-cfb", "aes192-cbc", "aes192-cbc-pkcs7", "aes192-ofb", "aes256-ecb", "aes256-cbc",
 * "aes256-cbc-pkcs7", "aes256-cfb", "aes256-ofb", "blowfish-ecb", "blowfish-cbc-pkcs7", "blowfish-cbc",
 * "blowfish-cfb", "blowfish-ofb", "tripledes-ecb", "tripledes-cbc", "des-ecb", "des-ecb-pkcs7", "des-cbc",
 * "des-cbc-pkcs7", "des-cfb", "des-ofb", "cast5-ecb", "cast5-cbc", "cast5-cbc-pkcs7", "cast5-cfb", "cast5-ofb")
 *
 * and we'll do : (
 * "aes128-cbc-pkcs7", "aes192-cbc-pkcs7",
 * "aes256-cbc-pkcs7", "blowfish-cbc-pkcs7", "tripledes-cbc",
 * "des-cbc-pkcs7", "cast5-cbc-pkcs7")
 */
bool Cipher::checkCipherAvailability(QString currentCipher) { return QCA::isSupported(currentCipher.toAscii()+"-"+"cbc"+"-"+"pkcs7"); }

QString Cipher::getErrorTitle() { return this->errorTitle; }

QString Cipher::getErrorMsg() { return this->errorMsg; }

bool Cipher::getSuccess() { return this->success; }

void Cipher::stopOperation() { this->canceled=true; }

void Cipher::emitProgression() {
    if(this->operation.contains("cipher"))
        // Safety reasons : if we're doin checksums or current operation already failed, can't say progression.
            emit progressionChanged((int)((out->size()*100)/in->size()));
}


/**
 * @brief Cipher::encipher : encipher a list of file with a single password
 * @param currentCipher : cipher to use
 * @param inputFiles : list of files to encipher
 * @param password : password to use
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 * @return 20 : encipherment canceled
 * @return 42 : encipherment failed
 */
int Cipher::encipher(QString currentCipher, QString password) {

    emit stepChanged("Calcul de la clé privée & autres pré-requis");
    QCA::SecureArray salt = "testtesttesttest";
    //QCA::SecureArray salt = QCA::Random::randomArray(16);

    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 250000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());


    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    emit stepChanged("Configuration du chiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                     QCA::Cipher::DefaultPadding, QCA::Encode,
                                     key, iv);


    //the file we want to encrypt...
    emit stepChanged("Ouverture de " + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName()); //  todo: filename sans chemin
    if (!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors de l'ouverture du fichier " + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName();
        this->errorTitle = "Erreur lors du chiffrement";
        this->success=false;
        return 1;
    }

    //... into this file
    emit stepChanged("Ouverture de " + QFileInfo(in->fileName()).fileName()+ENC_FILE_EXT);
    out = new QFile(in->fileName() + ENC_FILE_EXT);
    if (!out->open(QIODevice::WriteOnly)) {
        emit stepChanged("Erreur lors de l'écriture");
        this->errorMsg = "Erreur lors de l'écriture dans le fichier " + QFileInfo(out->fileName()).fileName();
        this->errorTitle = "Erreur lors du chiffrement";
        this->success=false;
        return 2;
    }


    emit stepChanged("Chiffrement de " + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName());
    /*we write magic 8 bytes + salt (16 bytes for now) */
    out->write("Salted__" + salt.toByteArray());

    QCA::SecureArray encipheredData;

    while(!in->atEnd()) {

        /*
         * If cancel was called, stop immediatly current operation
         */
        if(this->canceled) {
            out->close();
            in->close();
            this->errorMsg = "Chiffrement de " + QFileInfo(in->fileName()).fileName() + " annulé.";
            this->errorTitle = "Chiffrement annulé";
            this->success=false;
            emit stepChanged("Chiffrement annulé");
            return 20;
        }

        QCA::SecureArray secureData = in->read(32768); // TODO: static value

        //we encrypt the data
        encipheredData = cipher.update(secureData);

        //checks if encryption succeded
        if (!cipher.ok())
        {
            emit stepChanged("Erreur lors du chiffrement");
            this->errorMsg = "Erreur lors du chiffrement des données de " + QFileInfo(in->fileName()).fileName();
            this->errorTitle = "Erreur lors du chiffrement";
            this->success=false;
            return 42;
        }

        out->write(encipheredData.data(),(qint64) encipheredData.size());
    }

    encipheredData = cipher.final();
    out->write(encipheredData.data(),(qint64) encipheredData.size());

    //checks if final succeded
    if (!cipher.ok())
    {
        emit stepChanged("Erreur lors du chiffrement");
        this->errorMsg = "Erreur lors du padding des données de " + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du padding";
        this->success=false;
        return 42;
    }


    out->close();
    in->close();

    emit stepChanged("Chiffrement terminé");
    qDebug() << "Chiffrement terminé ! :)";
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
 * @return 20 : decipherment canceled
 * @return 42 : decipherment failed
 */
int Cipher::decipher(QString currentCipher, QString password) {

    //the file we want to decrypt
    emit stepChanged("Ouverture de " + QFileInfo(in->fileName()).fileName());
    if (!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du déchiffrement";
        this->success=false;
        return 1;
    }

    out = new QFile(in->fileName().split(ENC_FILE_EXT).first()); /** TODO: tester l'existance du fichier, ou si source=dest + extension .p7?*/
    emit stepChanged("Écriture de " + QFileInfo(out->fileName()).fileName());
    if (!out->open(QIODevice::WriteOnly)) {
        emit stepChanged("Erreur lors de l'écriture");
        this->errorMsg = "Erreur lors de l'écriture dans le fichier" + QFileInfo(out->fileName()).fileName().split(ENC_FILE_EXT).first();
        this->errorTitle = "Erreur lors du déchiffrement";
        this->success=false;
        return 2;
    }

    emit stepChanged("Calcul de la clé privée & autres pré-requis");

    in->read(8); //ignore first 8 bytes
    QCA::SecureArray salt = in->read(16);


    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, 256, 250000); //100K or more

    QCA::Hash hash("md5");
    hash.update(key.toByteArray());
    QCA::InitializationVector iv = QCA::SecureArray(hash.final());

    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    emit stepChanged("Configuration du déchiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, QCA::Cipher::CBC,
                                     QCA::Cipher::DefaultPadding, QCA::Decode,
                                     key, iv);

    QCA::SecureArray decryptedData;

    emit stepChanged("Déchiffrement de " + QFileInfo(in->fileName()).fileName());
    while(!in->atEnd()) {

        /*
         * If cancel was called, stop immediatly current operation
         */
        if(this->canceled) {
            out->close();
            in->close();
            this->errorMsg = "Déchiffrement de " + QFileInfo(in->fileName()).fileName() + " annulé.";
            this->errorTitle = "Déchiffrement annulé";
            this->success=false;
            emit stepChanged("Déchiffrement annulé");
            return 20;
        }

        QByteArray secureData=in->read(32768); // TODO: static value

        //decrypt the encrypted data
        decryptedData = cipher.update(secureData);

        //checks if decryption succeded
        if (!cipher.ok())
        {
            emit stepChanged("Erreur lors du déchiffrement");
            this->errorMsg = "Erreur lors du déchiffrement de " + QFileInfo(in->fileName()).fileName();
            this->errorTitle = "Erreur lors du déchiffrement";
            this->success=false;
            return 42;
        }
        out->write(decryptedData.data(),(qint64) decryptedData.size());

    }


    decryptedData = cipher.final();

    //checks if final succeded
    if (!cipher.ok())
    {
        emit stepChanged("Erreur lors du déchiffrement");
        this->errorMsg = "Erreur lors du déchiffrement final de " + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du déchiffrement";
        this->success=false;
        return 42;
    }

    out->write(decryptedData.data(),(qint64) decryptedData.size());

    out->close();
    in->close();

    emit stepChanged("Déchiffrement terminé");
    return 0;
}

/**
 * @brief Cipher::makeChecksum
 * @param inputFiles : files to analyze & create their associated .md5
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't write into file
 */
int Cipher::makeChecksum() {

    //ui->progressBar->setValue(-1);
    emit stepChanged("Création du fichier checksum de " + QFileInfo(in->fileName()).fileName());
    if(!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors l'ouverture du fichier" + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 1;
    }
    QCA::Hash hash("md5");
    hash.update(in);
    QString md5hash = hash.final().toByteArray().toHex();
    in->close();

    /* TODO: check errors ? */

    out = new QFile(QFileInfo(in->fileName()).fileName() + ".md5");
    if(!out->open(QIODevice::WriteOnly)) {
        emit stepChanged("Erreur lors de l'écriture du fichier");
        this->errorMsg = "Erreur lors de la création du fichier" + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName() + ".md5";
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 2;
    }
    out->write(md5hash.toAscii(), (quint64) md5hash.size());
    out->close();


    return 0;
}

/**
 * @brief Cipher::checkChecksum : check a list of .md5 with their associated files
 * @param inputFiles : files to check
 * @param checksumFiles : .md5 to compare
 * @return 0 : ok
 * @return 1 : couldn't open a file
 * @return 2 : couldn't open checksum
 * @return 10 : names between files and .md5 differ
 * @return 42 : md5 check fails
 */
int Cipher::checkChecksum() {
    emit stepChanged("Vérification de la somme de contrôle");

    if(QFileInfo(in->fileName()).fileName().split(ENC_FILE_EXT).first().compare(QFileInfo(checksum->fileName()).fileName().split(".md5").first())!=0) {
        emit stepChanged("Erreur lors de la correspondance des fichiers");
        this->errorMsg = "La vérification de l'intégrité du fichier a échoué. Vérifiez que les noms correspondent :<br /><br />fichier.txt --> fichier.txt.md5";
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 10;
    }

    in->setFileName(in->fileName().split(ENC_FILE_EXT).first());
    if(!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName().split(ENC_FILE_EXT).first().toAscii();
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 1;
    }

    if(!checksum->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur de l'ouverture du fichier");
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + QFileInfo(checksum->fileName()).fileName();
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 2;
    }


    QString contentOfChecksumFile = checksum->readAll();
    contentOfChecksumFile=contentOfChecksumFile.split("\n").first();

    QCA::Hash hash("md5");
    hash.update(in);
    QString md5hash = hash.final().toByteArray().toHex();
    in->close();
    checksum->close();

    if(contentOfChecksumFile.compare(md5hash) != 0) {
        emit stepChanged("Erreur lors de la vérification du fichier");
        this->errorMsg = "Les fichiers<br />" + QFileInfo(in->fileName()).fileName().split(ENC_FILE_EXT).first() + "<br />et<br />" + QFileInfo(checksum->fileName()).fileName() + "<br />ne correspondent pas";
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 42;
    }

    return 0;
}
