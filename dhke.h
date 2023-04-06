#ifndef DHKE_H
#define DHKE_H

#include <QObject>
#include <openssl/engine.h>

class DHKE : public QObject
{
    Q_OBJECT
public:
    explicit DHKE(QObject *parent = nullptr);
    ~DHKE();

    enum eSecretTypes{
        eSecretType_Static,
        eSecretType_Ephemeral
    };

public slots:

    bool setEngine(const std::string& engineName);
    QPair<QByteArray, QByteArray> gen_ECC_keypair();
    QByteArray sign_data(QByteArray dataToSign);
    bool verify_sign(QByteArray rawData, QByteArray signedData);
    QByteArray gen_secret(DHKE::eSecretTypes type);
    QByteArray hmac_sha256(QByteArray secret_key, QByteArray msg);

private:
    ENGINE *engine;

signals:

};

#endif // DHKE_H
