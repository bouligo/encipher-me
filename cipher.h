#ifndef CIPHER_H
#define CIPHER_H

#include <QThread>
#include <QFile>
#include <QtCrypto>
#include <QDebug>
#include <QFileInfo>

class Cipher : public QThread
{
    Q_OBJECT

public:
    Cipher();

    /** *************
     * Main methods *
     ************ **/
    bool startOperation(QString newOperation, QString inputFile, QString outputFile, QString currentCipher = "", QString pass = "", QString checksum = "", QString padding = "pkcs7", QString mode = "cbc");
    void stopOperation();

    /** ******
     * Tools *
     ***** **/
    bool checkCipherAvailability(QString currentCipher);
    void initState();

    /** ******************
     * Getters / Setters *
     ***************** **/
    QString getErrorTitle();
    QString getErrorMsg();
    bool getSuccess();
    bool getCanceled();

protected:
    /**
     * Inherited from QThread : protected, because in current architecture,
     * there is no point calling directly run(). Rather call startOperation()
     */
    virtual void run();


    /** *****************
     * Basic operations *
     **************** **/
    int encipher(QString currentCipher, QString password);
    int decipher(QString currentCipher, QString password);
    int makeChecksum();
    int checkChecksum();


    /** ***********
     * Attributes *
     ********** **/
    QString errorMsg, errorTitle, operation, algo, password, fileExtension;
    QCA::Cipher::Padding padding;
    QCA::Cipher::Mode cipherMode;
    QFile *in, *out, *checksum;
    bool success,canceled,isWorking;
    int keySize;

signals:
    void stepChanged(QString text);
    int progressionChanged(int progression);

private slots:
    void emitProgression();
};

#endif // CIPHER_H
