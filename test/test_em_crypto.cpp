#include <gtest/gtest.h>
#include <string>
#include <memory>

#include <cjson/cJSON.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/obj_mac.h>
#include <openssl/err.h>

#include "em_crypto.h" 



class EmCryptoTests : public ::testing::Test {
protected:
    void SetUp() override {
        auto sig_x = em_crypto_t::base64url_decode(test_sig_x);
        ASSERT_NE(sig_x, std::nullopt);
        auto sig_y = em_crypto_t::base64url_decode(test_sig_y);
        ASSERT_NE(sig_y, std::nullopt);
        signing_key = em_crypto_t::create_ec_key_from_coordinates(*sig_x, *sig_y, test_priv_proto_key, test_sig_curve);
        ASSERT_NE(signing_key, nullptr);
        printf("Signing Key\n");
        if (EVP_PKEY_print_public_fp(stdout, signing_key, 0, NULL) < 1) {
            auto err = ERR_get_error();
            printf("Failed to print public key: %s\n", ERR_error_string(err, NULL));
        }
        if (EVP_PKEY_print_private_fp(stdout, signing_key, 0, NULL) < 1) {
            auto err = ERR_get_error();
            printf("Failed to print private key: %s\n", ERR_error_string(err, NULL));
        }
    }

    void TearDown() override {
        printf("Tearing Down\n");
        if (signing_key) {
            em_crypto_t::free_key(signing_key);
        }
    }

    std::string remove_whitespace(std::string str) {
        str.erase(std::remove_if(str.begin(), str.end(), 
                  [](unsigned char c) { return std::isspace(c); }),
                  str.end());
        return str;
    }

// MUTABLES
    SSL_KEY *signing_key = nullptr;

// CONSTANTS

    const std::string basic_base64_test_str = "Hello+Mesh/World";


/*
    JWS Data fetched from EasyConnect 4.2.2 (Figures 13, 14, and 15)
*/
    const std::string test_jws_body_data = remove_whitespace(R"({
        "groups":
        [
            {"groupId":"home","netRole":"sta"},
            {"groupId":"cottage","netRole":"sta"}
        ],
        "netAccessKey":
        {
            "kty":"EC",
            "crv":"P-256",
            "x":"Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA",
            "y":"LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU"
        },
        "expiry":"2019-01-31T22:00:00+02:00"
    })");

    // Taken from "netAccessKey" above
    // These are the same as the Protocol Key in EasyConnect Appendix B.1 (Responder Values)
    const std::string test_sig_curve = "P-256";
    const std::string test_sig_x = "Xj-zV2iEiH8XwyA9ijpsL6xyLvDiIBthrHO8ZVxwmpA";
    const std::string test_sig_y = "LUsDBmn7nv-LCnn6fBoXKsKpLGJiVpY_knTckGgsgeU";
    // Taken Specifically from Appendix B.1
    const std::vector<uint8_t> test_priv_proto_key = {
        0xf7, 0x98, 0xed, 0x2e, 0x19, 0x28, 0x6f, 0x6a,
        0x6e, 0xfe, 0x21, 0x0b, 0x18, 0x63, 0xba, 0xdb,
        0x99, 0xaf, 0x2a, 0x14, 0xb4, 0x97, 0x63, 0x4d,
        0xbf, 0xd2, 0xa9, 0x73, 0x94, 0xfb, 0x5a, 0xa5
    };

    const std::string test_enc_jws_body = 
    "eyJncm91cHMiOlt7Imdyb3VwSWQiOiJob21lIiwibmV0Um9sZSI6InN0YSJ9LHsiZ3JvdXBJZCI6ImNvdHRh"
    "Z2UiLCJuZXRSb2xlIjoic3RhIn1dLCJuZXRBY2Nlc3NLZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIs"
    "IngiOiJYai16VjJpRWlIOFh3eUE5aWpwc0w2eHlMdkRpSUJ0aHJITzhaVnh3bXBBIiwieSI6IkxVc0RCbW43"
    "bnYtTENubjZmQm9YS3NLcExHSmlWcFlfa25UY2tHZ3NnZVUifSwiZXhwaXJ5IjoiMjAxOS0wMS0zMVQyMjow"
    "MDowMCswMjowMCJ9";

    const std::string test_jws_header_data = remove_whitespace(R"({
        "typ":"dppCon",
        "kid":"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE",
        "alg":"ES256"
    })");

    const std::string test_jws_header = "eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJrTWNlZ0RCUG1OWlZha0FzQlpPek9vQ3N2UWprcl9uRUFwOXVGLUVEbVZFIiwiYWxnIjoiRVMyNTYifQ";

    const std::string jws_sig = "8fJSNCpDjv5BEFfmlqEbBNTaHx2L6c_22Uvr9KYjtAw88VfvEUWiruECUSJCUVFqv1yDEE4RJVdTIw3aUDhlMw";

   
};

TEST_F(EmCryptoTests, Base64UrlDecode) {
    std::string test_data = "SGVsbG8rTWVzaC9Xb3JsZA";
    auto data = em_crypto_t::base64url_decode(test_data);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), basic_base64_test_str.length());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(data->data())), basic_base64_test_str);
}

TEST_F(EmCryptoTests, Base64UrlEncode) {
    std::string result = em_crypto_t::base64url_encode(basic_base64_test_str);
    EXPECT_EQ(result, "SGVsbG8rTWVzaC9Xb3JsZA");
}

TEST_F(EmCryptoTests, Base64Decode) {
    std::string test_data = "SGVsbG8rTWVzaC9Xb3JsZA==";
    auto data = em_crypto_t::base64url_decode(test_data);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), basic_base64_test_str.length());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(data->data())), basic_base64_test_str);
}

TEST_F(EmCryptoTests, Base64Encode) {
    std::string result = em_crypto_t::base64_encode(basic_base64_test_str);
    EXPECT_EQ(result, "SGVsbG8rTWVzaC9Xb3JsZA==");
}

TEST_F(EmCryptoTests, EncodeJWSHeader) {
    cJSON *jws_header = cJSON_Parse(test_jws_header_data.c_str());
    EXPECT_NE(jws_header, nullptr);

    char* jws_cstr = cJSON_PrintUnformatted(jws_header);
    std::string jws_str(jws_cstr);
    free(jws_cstr);
    cJSON_Delete(jws_header);
    std::string result = em_crypto_t::base64url_encode(jws_str);

    EXPECT_EQ(result, test_jws_header);
}

TEST_F(EmCryptoTests, EncodeJWSPayload) {
    cJSON *jws_body = cJSON_Parse(test_jws_body_data.c_str());
    EXPECT_NE(jws_body, nullptr);

    char* jws_cstr = cJSON_PrintUnformatted(jws_body);
    std::string jws_str(jws_cstr);
    free(jws_cstr);
    cJSON_Delete(jws_body);
    std::string result = em_crypto_t::base64url_encode(jws_str);

    EXPECT_EQ(result, test_enc_jws_body);
}

TEST_F(EmCryptoTests, DecodeJWSHeader) {
    auto data = em_crypto_t::base64url_decode(test_jws_header);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), test_jws_header_data.length());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(data->data())), test_jws_header_data);
}

TEST_F(EmCryptoTests, DecodeJWSPayload) {
    auto data = em_crypto_t::base64url_decode(test_enc_jws_body);
    EXPECT_NE(data, std::nullopt);
    EXPECT_EQ(data->size(), test_jws_body_data.length());
    EXPECT_EQ(std::string(reinterpret_cast<char*>(data->data())), test_jws_body_data); 
}

TEST_F(EmCryptoTests, SignJWSConnector) {

    ASSERT_NE(signing_key, nullptr);

    // Get JWS Header and Payload as Strings
    cJSON *jws_header = cJSON_Parse(test_jws_header_data.c_str());
    EXPECT_NE(jws_header, nullptr);

    cJSON *jws_body = cJSON_Parse(test_jws_body_data.c_str());
    EXPECT_NE(jws_body, nullptr);

    char* jws_header_cstr = cJSON_PrintUnformatted(jws_header);
    std::string jws_header_str(jws_header_cstr);
    free(jws_header_cstr);
    cJSON_Delete(jws_header);

    char* jws_body_cstr = cJSON_PrintUnformatted(jws_body);
    std::string jws_body_str(jws_body_cstr);
    free(jws_body_cstr);
    cJSON_Delete(jws_body);

    // Convert strings to base64url encoding
    std::string jws_header_enc = em_crypto_t::base64url_encode(jws_header_str);
    std::string jws_body_enc = em_crypto_t::base64url_encode(jws_body_str);

    // Concatenate using standard seperator and sign
    std::string data = jws_header_enc + "." + jws_body_enc;
    std::vector<uint8_t> data_vec(data.begin(), data.end());

    auto sig = em_crypto_t::sign_data_ecdsa(data_vec, signing_key, EVP_sha256());
    ASSERT_NE(sig, std::nullopt);

    bool did_verify = em_crypto_t::verify_signature_with_context(data_vec, *sig, signing_key, EVP_sha256());
    EXPECT_TRUE(did_verify);
}


    