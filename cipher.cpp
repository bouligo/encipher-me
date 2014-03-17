#include "cipher.h"

Cipher::Cipher()
{
    //initialize QCA
    //QCA::Initializer init = QCA::Initializer();
    QCA::init();

    //    qDebug() << QCA::Cipher::supportedTypes();
    //    qDebug() << QCA::Hash::supportedTypes();
    //    qDebug() << QCA::isSupported("sha1");

    initState();
}

/** ***************
 * Tools & slots  *
 ************** **/

bool Cipher::checkCipherAvailability(QString currentCipher) { return QCA::isSupported(currentCipher.toAscii()); }

QString Cipher::getErrorTitle() { return this->errorTitle; }

QString Cipher::getErrorMsg() { return this->errorMsg; }

bool Cipher::getSuccess() { return this->success; }

bool Cipher::getCanceled() { return this->canceled; }

void Cipher::stopOperation() { this->canceled=true; }

void Cipher::emitProgression() {
    if(this->operation.contains("cipher") && this->isWorking)
        // Safety reasons : if we're doin checksums or if no encipherment operation is proceeded, can't say progression.
        emit progressionChanged((int)((out->size()*100)/in->size()));
    //    else
    //        emit progressionChanged(0);
}

void Cipher::initState() {
    /*
     * Default error msg Initialization
     */
    this->errorMsg="Unknown Error";
    this->errorTitle="Unknown Error";
    this->success=true;
    this->canceled=false;
    this->isWorking=false;
}

/** ***************
 * Core functions *
 ************** **/


/**
 * @brief Cipher::startOperation : main entry point for other classes
 * @param newOperation : can be encipher, decipher, ...
 * @param inputFile : the file to process
 * @param currentCipher : algorithm to use
 * @param pass : password
 * @param checksum : checksum file (if newOperation.equals(checkChecksum)
 */


/**
 * @brief Cipher::run : inherited by QThread
 */
void Cipher::run() {

    initState();

    if(this->operation.contains("encipher"))
        this->encipher(this->algo, this->password);
    if(this->operation.contains("decipher"))
        this->decipher(this->algo, this->password);
    if(this->operation.contains("makeChecksum"))
        this->makeChecksum();
    if(this->operation.contains("checkChecksum"))
        this->checkChecksum();
}


/**
 * @brief Cipher::startOperation : put right parameters into attributes, and then call run()
 * @param newOperation : operation to do
 * @param inputFile : input file (thx captain)
 * @param currentCipher : algorith to use
 * @param pass : password
 * @param checksum : checksum file
 */
bool Cipher::startOperation(QString newOperation, QString inputFile, QString outputFile,QString currentCipher, QString pass, QString checksum, QString padding, QString mode) {

    /*
     * First, check if the cipher is supported in current configuration
     */
    emit stepChanged("Vérification des pré-requis");
    emit progressionChanged(0); //manual refresh of QProgressBar in instance Progression

    bool isCipherAvailable=true;
    if(newOperation.contains("Checksum"))
        isCipherAvailable=checkCipherAvailability(currentCipher);
    else
        isCipherAvailable=checkCipherAvailability(currentCipher + "-" + mode + (padding.isEmpty() ? "" : "-" + padding));

    if(!isCipherAvailable) {
        emit stepChanged("Erreur");
        this->errorMsg = "L'algorithme désiré <b>" + currentCipher + "</b> n'est pas supporté par la configuration courante.";
        this->errorTitle = "Erreur";
        this->success=false;
        return false;
    }


    this->operation = newOperation;
    this->algo = currentCipher;

    if(inputFile.compare(outputFile)==0) {
        this->errorMsg="Les fichiers sources et destination sont identiques :<br />" + inputFile;
        this->errorTitle="Erreur";
        this->success=false;
        return false;
    }

    this->in = new QFile(inputFile);
    this->out = new QFile(outputFile);
    this->password = pass;
    this->checksum = new QFile(checksum);

    if(padding.contains("pkcs7"))
        this->padding = QCA::Cipher::PKCS7;
    else
        this->padding = QCA::Cipher::NoPadding;


    if(mode.contains("cbc"))
        this->cipherMode = QCA::Cipher::CBC;
    else if(mode.contains("cfb"))
        this->cipherMode = QCA::Cipher::CFB;
    else if(mode.contains("ofb"))
        this->cipherMode = QCA::Cipher::OFB;
    else
        this->cipherMode = QCA::Cipher::CBC;

    if(currentCipher.contains("aes128"))
        this->keySize=128/8;
    else if(currentCipher.contains("aes192"))
        this->keySize=192/8;
    else if(currentCipher.contains("aes256"))
        this->keySize=256/8;
    else if(currentCipher.contains("blowfish"))
        this->keySize=448/8;
    else if(currentCipher.contains("des"))
        this->keySize=56/8;
    else if(currentCipher.contains("cast5"))
        this->keySize=128/8;

    this->start();

    return true;
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
    QCA::SecureArray salt = QCA::Random::randomArray(16);
    QCA::InitializationVector iv = QCA::Random::randomArray(16);

    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, this->keySize, 250000); //100K or more

    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    emit stepChanged("Configuration du chiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, this->cipherMode,
                                     this->padding, QCA::Encode,
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
    emit stepChanged("Ouverture de " + QFileInfo(out->fileName()).fileName());
    //out = new QFile(in->fileName() + this->fileExtension);
    if (!out->open(QIODevice::WriteOnly)) {
        emit stepChanged("Erreur lors de l'écriture");
        this->errorMsg = "Erreur lors de l'écriture dans le fichier " + QFileInfo(out->fileName()).fileName();
        this->errorTitle = "Erreur lors du chiffrement";
        this->success=false;
        return 2;
    }


    emit stepChanged("Chiffrement de " + QFileInfo(QFileInfo(in->fileName()).fileName()).fileName());
    /*we write magic 8 bytes + salt (16 bytes for now) + IV */
    out->write("Salted__" + salt.toByteArray() + iv.toByteArray());

    QCA::SecureArray encipheredData;

    this->isWorking=true; //allows to emitProgression()
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
            this->canceled=true;
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


    //checks if final succeded
    if (!cipher.ok())
    {
        emit stepChanged("Erreur lors du chiffrement");
        this->errorMsg = "Erreur lors du padding des données de " + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du padding";
        this->success=false;
        out->close();
        in->close();
        this->isWorking=false;
        return 42;
    }
    out->write(encipheredData.data(),(qint64) encipheredData.size());

    out->close();
    in->close();
    this->isWorking=false;

    emit stepChanged("Chiffrement terminé");
    emit progressionChanged(100);
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

    //out = new QFile(in->fileName().split(this->fileExtension).first()); /** TODO: tester l'existance du fichier, ou si source=dest + extension .p7?*/
    emit stepChanged("Écriture de " + QFileInfo(out->fileName()).fileName());
    if (!out->open(QIODevice::WriteOnly)) {
        emit stepChanged("Erreur lors de l'écriture");
        this->errorMsg = "Erreur lors de l'écriture dans le fichier" + QFileInfo(out->fileName()).fileName();
        this->errorTitle = "Erreur lors du déchiffrement";
        this->success=false;
        return 2;
    }

    emit stepChanged("Calcul de la clé privée & autres pré-requis");

    in->read(8); //ignore first 8 bytes
    QCA::SecureArray salt = in->read(16);
    QCA::InitializationVector iv = in->read(16);


    QCA::PBKDF2 pbkdf2;
    QCA::SymmetricKey key = pbkdf2.makeKey(password.toAscii(), salt, this->keySize, 250000); //100K or more


    /*
     * Setup the cipher, with algorythm, method, padding, direction, key and init. vector
     */
    emit stepChanged("Configuration du déchiffrement");
    QCA::Cipher cipher = QCA::Cipher(currentCipher, this->cipherMode,
                                     this->padding, QCA::Decode,
                                     key, iv);

    QCA::SecureArray decryptedData;

    emit stepChanged("Déchiffrement de " + QFileInfo(in->fileName()).fileName());
    this->isWorking=true; //allows to emitProgression()
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
            this->canceled=true;
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
        out->close();
        in->close();
        this->isWorking=false;
        return 42;
    }

    out->write(decryptedData.data(),(qint64) decryptedData.size());

    out->close();
    in->close();
    this->isWorking=false;

    emit stepChanged("Déchiffrement terminé");
    emit progressionChanged(100);
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

    emit stepChanged("Création du fichier checksum de " + QFileInfo(in->fileName()).fileName());
    if(!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors l'ouverture du fichier" + QFileInfo(in->fileName()).fileName();
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 1;
    }
    QCA::Hash hash(this->algo);
    hash.update(in);
    QString md5hash = hash.final().toByteArray().toHex();
    in->close();

    /* TODO: check errors ? */
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
    emit stepChanged("Vérification de " + QFileInfo(in->fileName()).fileName());

    if(QFileInfo(in->fileName()).fileName().compare(QFileInfo(checksum->fileName()).fileName().split("."+this->algo).first())!=0) {
        emit stepChanged("Erreur lors de la correspondance des fichiers");
        this->errorMsg = "La vérification de l'intégrité du fichier a échoué. Vérifiez que les noms correspondent :<br /><br />fichier.txt --> fichier.txt.md5";
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 10;
    }

    if(!in->open(QIODevice::ReadOnly)) {
        emit stepChanged("Erreur lors de l'ouverture");
        this->errorMsg = "Erreur lors de l'ouverture du fichier" + QFileInfo(in->fileName()).fileName().toAscii();
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

    QCA::Hash hash(this->algo);
    hash.update(in);
    QString md5hash = hash.final().toByteArray().toHex();
    in->close();
    checksum->close();

    if(contentOfChecksumFile.compare(md5hash) != 0) {
        emit stepChanged("Erreur lors de la vérification du fichier");
        this->errorMsg = "Les fichiers<br />" + QFileInfo(in->fileName()).fileName() + "<br />et<br />" + QFileInfo(checksum->fileName()).fileName() + "<br />ne correspondent pas";
        this->errorTitle = "Erreur lors du controle checksum";
        this->success=false;
        return 42;
    }

    return 0;
}
