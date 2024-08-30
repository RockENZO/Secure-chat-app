#include "encryption.h"
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <iostream>

std::string Encryption::encryptRSA(const std::string& publicKey, const std::string& message) {
    // Load public key
    BIO* bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    RSA* rsaPubKey = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    BIO_free(bio);

    // Encrypt message
    std::string encryptedMessage(RSA_size(rsaPubKey), '\0');
    int result = RSA_public_encrypt(message.size(), (unsigned char*)message.c_str(),
                                    (unsigned char*)encryptedMessage.data(), rsaPubKey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsaPubKey);
    if (result == -1) {
        std::cerr << "Error encrypting message with RSA" << std::endl;
    }
    return encryptedMessage;
}

std::string Encryption::decryptRSA(const std::string& privateKey, const std::string& encryptedMessage) {
    // Load private key
    BIO* bio = BIO_new_mem_buf(privateKey.data(), privateKey.size());
    RSA* rsaPrivKey = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    BIO_free(bio);

    // Decrypt message
    std::string decryptedMessage(RSA_size(rsaPrivKey), '\0');
    int result = RSA_private_decrypt(encryptedMessage.size(), (unsigned char*)encryptedMessage.data(),
                                     (unsigned char*)decryptedMessage.data(), rsaPrivKey, RSA_PKCS1_OAEP_PADDING);
    RSA_free(rsaPrivKey);
    if (result == -1) {
        std::cerr << "Error decrypting message with RSA" << std::endl;
    }
    return decryptedMessage;
}

std::string Encryption::encryptAES(const std::string& key, const std::string& message) {
    // AES encryption
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[AES_BLOCK_SIZE];
    RAND_bytes(iv, AES_BLOCK_SIZE);

    int outLen1 = message.size() + AES_BLOCK_SIZE;
    unsigned char* ciphertext = new unsigned char[outLen1];
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, (unsigned char*)key.data(), iv);
    EVP_EncryptUpdate(ctx, ciphertext, &outLen1, (unsigned char*)message.c_str(), message.size());

    EVP_CIPHER_CTX_free(ctx);
    std::string encryptedMessage(reinterpret_cast<char*>(ciphertext), outLen1);
    delete[] ciphertext;