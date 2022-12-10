#include "dhke.h"
#include <QDebug>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>

DHKE::DHKE(QObject *parent)
    : QObject{parent}
{

}

DHKE::~DHKE()
{

}

QPair<QByteArray, QByteArray> DHKE::gen_ECC_keypair()
{
    // Load the TPM2TSS engine
    ENGINE *engine = ENGINE_by_id("tpm2tss");
    if (!engine) {
        qWarning() << "Error loading TPM2TSS engine";
    }
    // Set the engine as the default for all algorithms
     if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
         qWarning() << "Error setting TPM2TSS as default engine";
     }

    // Create the key pair
    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp256k1);
    EC_KEY_generate_key(key);

    QByteArray privateKey(BN_bn2hex(EC_KEY_get0_private_key(key)));
    QByteArray publicKey(EC_POINT_point2hex(EC_KEY_get0_group(key), EC_KEY_get0_public_key(key), POINT_CONVERSION_COMPRESSED, NULL));

    EC_KEY_free(key);
    ENGINE_free(engine);

    return qMakePair(privateKey, publicKey);
}

QByteArray DHKE::sign_data(QByteArray dataToSign)
{
    // Load the TPM2TSS engine
    ENGINE *engine = ENGINE_by_id("tpm2tss");
    if (!engine) {
        qWarning() << "Error loading TPM2TSS engine";
    }
    // Set the engine as the default for all algorithms
     if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
         qWarning() << "Error setting TPM2TSS as default engine";
     }

    EVP_PKEY *privateKey = NULL;
    FILE *keyFile = fopen("self_private_sign_key.pem", "rb");
    if (!keyFile) {
        qInfo() << "Error opening private key file";
    }
    privateKey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    if (!privateKey) {
        qInfo() << "Error reading private key";
    }
    fclose(keyFile);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_SignInit(mdctx, EVP_sha256());
    EVP_SignUpdate(mdctx, dataToSign.data(), dataToSign.size());
    unsigned char *signature = NULL;
    unsigned int signatureLen{0};
    /* Determine buffer length */
    EVP_SignFinal(mdctx, NULL, &signatureLen, privateKey);

    signature = new unsigned char[signatureLen];
    EVP_SignFinal(mdctx, signature, &signatureLen, privateKey);

    QByteArray signContainer(reinterpret_cast<char*>(signature));

    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(privateKey);
    delete[] signature;
    ENGINE_free(engine);

    return signContainer;
}

bool DHKE::verify_sign(QByteArray rawData, QByteArray signedData)
{
    // Load the TPM2TSS engine
    ENGINE *engine = ENGINE_by_id("tpm2tss");
    if (!engine) {
        qWarning() << "Error loading TPM2TSS engine";
    }
    // Set the engine as the default for all algorithms
     if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
         qWarning() << "Error setting TPM2TSS as default engine";
     }

    EVP_PKEY *publicKey = NULL;
    FILE *keyFile = fopen("peer_public_sign_key.pem", "rb");
    if (!keyFile) {
        qWarning() << "Error opening peer public key file";
    }
    publicKey = PEM_read_PUBKEY(keyFile, NULL, NULL, NULL);
    if (!publicKey) {
        qWarning() << "Error reading peer public key";
    }
    fclose(keyFile);

    EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
    EVP_VerifyInit(mdctx, EVP_sha256());
    EVP_VerifyUpdate(mdctx, rawData.data(), rawData.size());

    bool isVerified;
    int result = EVP_VerifyFinal(mdctx, reinterpret_cast<unsigned char*>(signedData.data()), signedData.size(), publicKey);
    if(result == 1){
        qWarning() << "Verified OK.";
        isVerified = true;
    }
    else{
        qWarning() << "Verify Failed.";
        isVerified = false;
    }

    EVP_MD_CTX_destroy(mdctx);
    EVP_PKEY_free(publicKey);
    ENGINE_free(engine);
    return isVerified;

}

QByteArray DHKE::gen_secret(DHKE::eSecretTypes type)
{
    QByteArray privateKeyFile;
    QByteArray publicKeyFile;
    if(type == eSecretType_Static){
        privateKeyFile = "self_private_static_key.pem";
        publicKeyFile = "peer_public_static_key.pem";
    }
    else {
        privateKeyFile = "self_private_ephemeral_key.pem";
        publicKeyFile = "peer_public_ephemeral_key.pem";
    }

//    ENGINE *engine = ENGINE_by_id("openssl");
    // Load the TPM2TSS engine
    ENGINE *engine = ENGINE_by_id("tpm2tss");
    if (!engine) {
        qWarning() << "Error loading TPM2TSS engine";
        return "ERR";
    }
    // Set the engine as the default for all algorithms
     if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
         qWarning() << "Error setting TPM2TSS as default engine";
         return "ERR";
     }
    // Load the local private key from a file
    EVP_PKEY *private_key = NULL;
    FILE *priv_key_file = fopen(privateKeyFile.constData(), "r");
    if (!priv_key_file) {
      qWarning() << "Failed to open private key file";
      return "ERR";
    }
    private_key = PEM_read_PrivateKey(priv_key_file, NULL, NULL, NULL);

    if (!private_key) {
      qWarning() << "Failed to read private key";
      return "ERR";
    }
    fclose(priv_key_file);

    // Load the peer's public key from a file
    EVP_PKEY *public_key = NULL;
    FILE *pub_key_file = fopen(publicKeyFile.constData(), "r");
    if (!pub_key_file) {
      qWarning() << "Failed to peer public key file";
      return "ERR";
    }
    public_key = PEM_read_PUBKEY(pub_key_file, NULL, NULL, NULL);
    if (!public_key) {
      qWarning() << "Failed to read peer public key";
      return "ERR";
    }
    fclose(pub_key_file);

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(private_key, engine);
    if(!ctx){
        qWarning() << "error";
        return "ERR";
    }
    if(EVP_PKEY_derive_init(ctx) <= 0){
        qWarning() << "error";
        return "ERR";
    }
    if(EVP_PKEY_derive_set_peer(ctx, public_key) <= 0){
        qWarning() << "error";
        return "ERR";
    }

    unsigned char *secret;
    size_t secret_len;

    /* Determine buffer length */
    if (EVP_PKEY_derive(ctx, NULL, &secret_len) <= 0){
        qWarning() << "error";
        return "ERR";
    }

    secret = reinterpret_cast<unsigned char*>(OPENSSL_malloc(secret_len));
    if(!secret){
        qWarning() << "error";
        return "ERR";
    }

    if(EVP_PKEY_derive(ctx, secret, &secret_len) <= 0){
        qWarning() << "error";
        return "ERR";
    }

    QByteArray secretContainer(reinterpret_cast<char*>(secret));

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    EVP_PKEY_free(private_key);
    ENGINE_free(engine);
    return secretContainer;
}

QByteArray DHKE::hmac_sha256(QByteArray secret_key, QByteArray msg)
{
    // Load the TPM2TSS engine
    ENGINE *engine = ENGINE_by_id("tpm2tss");
    if (!engine) {
        qWarning() << "Error loading TPM2TSS engine";
        return "ERR";
    }
    // Set the engine as the default for all algorithms
     if (!ENGINE_set_default(engine, ENGINE_METHOD_ALL)) {
         qWarning() << "Error setting TPM2TSS as default engine";
         return "ERR";
     }
    unsigned char digest[32];
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, secret_key.data(), secret_key.size(), EVP_sha256(), nullptr);
    HMAC_Update(ctx, reinterpret_cast<unsigned char*>(msg.data()), msg.size());
    HMAC_Final(ctx, digest, nullptr);

    QByteArray digestContainer(reinterpret_cast<char*>(digest));

    HMAC_CTX_free(ctx);
    ENGINE_free(engine);
    return digestContainer;

}
