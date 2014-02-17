#ifndef CIPHER_H
#define CIPHER_H

#include <QThread>
#include <QFile>
#include <QtCrypto>
#include <QDebug>
#include <QFileInfo>

#define ENC_FILE_EXT ".p7"

class Cipher : public QThread
{
    Q_OBJECT

public:
    Cipher();

    /** *************
     * Main methods *
     ************ **/
    void startOperation(QString newOperation, QString inputFile, QString currentCipher = "", QString pass = "", QString checksum = "");
    void stopOperation();

    /** ******
     * Tools *
     ***** **/
    bool checkCipherAvailability(QString currentCipher);

    /** ******************
     * Getters / Setters *
     ***************** **/
    QString getErrorTitle();
    QString getErrorMsg();
    bool getSuccess();

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
    QString errorMsg, errorTitle, operation, algo, password;
    QFile *in, *out, *checksum;
    bool success,canceled,isWorking;

signals:
    void stepChanged(QString text);
    int progressionChanged(int progression);

private slots:
    void emitProgression();
};

#endif // CIPHER_H
