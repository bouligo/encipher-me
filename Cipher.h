#ifndef CIPHER_H
#define CIPHER_H
#include <QString>
#include <QtCrypto>

class Cipher
{
public:

    /**
     * Main methods
     */
    Cipher();
    int encipher(QString currentCipher, QString inputFiles, QString key);
    int decipher(QString currentCipher, QString inputFiles, QString password);
    int makeChecksum(QString inputFiles);
    int checkChecksum(QString inputFiles, QString checksumFiles);

    /**
     * Tools
     */
    QStringList getFileList(QString inputFiles);
    //bool checkCipherAvailability(QString currentCipher);

    /**
     * Error handling
     */
    QString getErrorTitle();
    QString getErrorMsg();


protected:
    QString errorMsg, errorTitle;

};

#endif // CIPHER_H
