#ifndef CIPHER_H
#define CIPHER_H

#include <QString>
#include <QtCrypto>
#include <QWidget>

namespace Ui {
class Cipher;
}

class Cipher : public QWidget
{
    Q_OBJECT

public:
    explicit Cipher(QWidget *parent = 0);
    ~Cipher();

    /**
     * Main methods
     */
    int encipher(QString currentCipher, QString inputFile, QString key);
    int decipher(QString currentCipher, QString inputFile, QString password);
    int makeChecksum(QString inputFile);
    int checkChecksum(QString inputFile, QString checksumFile);

    /**
     * Tools
     */
    bool checkCipherAvailability(QString currentCipher);

    /**
     * Error handling
     */
    QString getErrorTitle();
    QString getErrorMsg();

protected:
    QString errorMsg, errorTitle;

private:
    Ui::Cipher *ui;
};

#endif // CIPHER_H
