#include <iostream>
#include <websocketpp/config/asio_no_tls_client.hpp>
#include <websocketpp/client.hpp>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <json/json.h>
#include <functional>  // Include this for std::bind and std::placeholders

typedef websocketpp::client<websocketpp::config::asio_client> client;

client c;
websocketpp::connection_hdl hdl;

std::string base64_encode(const unsigned char* buffer, size_t length) {
    BIO* bio, * b64;
    BUF_MEM* bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free_all(bio);

    std::string encoded_data(bufferPtr->data, bufferPtr->length);
    BUF_MEM_free(bufferPtr);

    return encoded_data;
}

std::string generate_rsa_keypair(std::string& public_key) {
    RSA* rsa = RSA_new();
    BIGNUM* bn = BN_new();
    BN_set_word(bn, RSA_F4);
    RSA_generate_key_ex(rsa, 2048, bn, nullptr);

    BIO* pri = BIO_new(BIO_s_mem());
    BIO* pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, rsa, nullptr, nullptr, 0, nullptr, nullptr);
    PEM_write_bio_RSAPublicKey(pub, rsa);

    size_t pri_len = BIO_pending(pri);
    size_t pub_len = BIO_pending(pub);

    char* pri_key = (char*)malloc(pri_len + 1);
    char* pub_key = (char*)malloc(pub_len + 1);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    std::string private_key(pri_key, pri_len);
    public_key = std::string(pub_key, pub_len);

    BIO_free_all(pri);
    BIO_free_all(pub);
    RSA_free(rsa);
    BN_free(bn);
    free(pri_key);
    free(pub_key);

    return private_key;
}

void on_message(client* c, websocketpp::connection_hdl hdl, client::message_ptr msg) {
    std::cout << "Received: " << msg->get_payload() << std::endl;
}

int main() {
    try {
        std::string public_key;
        std::string private_key = generate_rsa_keypair(public_key);

        c.init_asio();  // Initialize ASIO

        c.set_message_handler(std::bind(&on_message, &c, std::placeholders::_1, std::placeholders::_2));

        std::string uri = "ws://localhost:9002";
        websocketpp::lib::error_code ec;
        client::connection_ptr con = c.get_connection(uri, ec);

        if (ec) {
            std::cout << "Could not create connection because: " << ec.message() << std::endl;
            return 0;
        }

        hdl = con->get_handle();
        c.connect(con);

        std::thread t([&]() { 
            try {
                c.run(); 
            } catch (const std::exception& e) {
                std::cerr << "Exception in thread: " << e.what() << std::endl;
            } catch (...) {
                std::cerr << "Unknown exception in thread!" << std::endl;
            }
        });

        Json::Value root;
        root["data"]["type"] = "hello";
        root["data"]["public_key"] = public_key;

        Json::StreamWriterBuilder writer;
        std::string message = Json::writeString(writer, root);

        c.send(hdl, message, websocketpp::frame::opcode::text);

        t.join();  // Wait for the thread to finish

    } catch (const websocketpp::exception& e) {
        std::cerr << "WebSocket++ exception: " << e.what() << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    } catch (...) {
        std::cerr << "Unknown exception occurred!" << std::endl;
    }

    return 0;
}