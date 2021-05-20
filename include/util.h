#ifndef INTERCOM_UTIL_H
#define INTERCOM_UTIL_H

#include <string>
#include <openssl/dh.h>
#include <assert.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <cstring>
#include <iostream>

using namespace std;

/**
 * Utility function to handle OPENSSL errors
 */
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

// *-*-*-*-*-*-*-*-*-*-* SERIALIZE & DESERIALIZE STUFF *-*-*-*-*-*-*-*-*-*-*

	// *** PUBKEY ***

unsigned char *pem_serialize_pubkey(EVP_PKEY *key, size_t *len)
{
	assert(key && len);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (PEM_write_bio_PUBKEY(bio, key) != 1) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	char *buf;
	*len = BIO_get_mem_data(bio, &buf);
	if (*len <= 0 || !buf) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	unsigned char *pubkey = (unsigned char*)malloc(*len);
	if (!pubkey)
		handleErrors();
	memcpy(pubkey, buf, *len);
	BIO_free(bio);
	return pubkey;
}

EVP_PKEY *pem_deserialize_pubkey(unsigned char *key, size_t len)
{
	assert(key);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (BIO_write(bio, key, len) != (int)len) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	EVP_PKEY *pubkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);
	if (!pubkey)
		handleErrors();
	BIO_free(bio);
	return pubkey;
}


	// *** CERTIFICATE ***

unsigned char *pem_serialize_certificate(X509 *cert, size_t *len)
{
	assert(cert && len);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
		handleErrors();
		return NULL;
	}
	if (PEM_write_bio_X509(bio, cert) != 1) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	char *buf;
	*len = BIO_get_mem_data(bio, &buf);
	if (*len <= 0 || !buf) {
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	unsigned char *certificate = (unsigned char*)malloc(*len);
	if (!certificate)
		handleErrors();
	memcpy(certificate, buf, *len);
	BIO_free(bio);
	return certificate;
}


X509* pem_deserialize_certificate(unsigned char *certificate, size_t len)
{
	assert(certificate);
	BIO *bio = BIO_new(BIO_s_mem());
	if (!bio) {
        cout<<"ER0"<<endl;
		handleErrors();
		return NULL;
	}
	if (BIO_write(bio, certificate, len) != (int)len) {
        cout<<"ER1"<<endl;
		handleErrors();
		BIO_free(bio);
		return NULL;
	}
	X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	if (!cert){
        cout<<"ER2"<<endl;
        handleErrors();
    }
	BIO_free(bio);
	return cert;
}


// *-*-*-*-*-*-*-*-*-*-* GCM ENCRYPT / GCM DECRYPT *-*-*-*-*-*-*-*-*-*-*


/**
 * gcm_encrypt: encrypt a message in aes-128 gcm mode
 * 
 * @param plaintext the message to encrypt
 * @param plaintext_len the length of the message to encrypt
 * @param aad additional data to add to the message
 * @param aad_len the length of the additional data portion
 * @param iv the random initialization vector prepend to the message
 * @param iv_len the length of the initialization vector
 * @param ciphertext the pointer to variable where to store the encrypted message
 * @param tag the nonce appended to the message
 * 
 * The function encrypt create a message in AES 128 bit mode GCM, cycling if the message size is 
 * greater than AES block size. Return the length of the encrypted text
 */ 
int gcm_encrypt(unsigned char *plaintext, size_t plaintext_len, 
                unsigned char *aad, size_t aad_len, 
                unsigned char *key,
                unsigned char *iv, size_t iv_len, 
                unsigned char *ciphertext, 
                unsigned char *tag) {

    EVP_CIPHER_CTX *ctx;
    int len;
    size_t ciphertext_len = 0;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout<<" Error in creating the context for encryption"<<std::endl;
        handleErrors();
    }
    // Initialise the encryption operation.
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        std::cout<<"Error in Initialising the encryption operation"<<std::endl;
        handleErrors();
    }
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        handleErrors();
    }


    while ( (ciphertext_len < (plaintext_len-8)) && plaintext_len > 8) {
        //cout << "Entra nel loop?" << endl;
        if(1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, 8)){
            std::cout<<"Error in performing encryption"<<std::endl;
            handleErrors();
        }
        ciphertext_len += len;
        plaintext_len -= len;
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &len, plaintext + ciphertext_len, plaintext_len)){
        std::cout<<"Error in performing encryption"<<std::endl;
        handleErrors();
    }
    ciphertext_len += len;
    
    //Finalize Encryption
    if(1 != EVP_EncryptFinal(ctx, ciphertext + ciphertext_len, &len)){
        std::cout<<"Error in finalizing encryption"<<std::endl;
        handleErrors();
    }
    ciphertext_len += len;
    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag)){
        std::cout<<"Error in retrieving the tag "<<std::endl;
        handleErrors();
    }
    /* Clean up */

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}



/**
 * Util function to decrypt server message
 * 
 * @param ciphertext the ciphertext to decrypt
 * @param ciphertext_len length of the message to decrypt
 * @param aad additional data to add in the message
 * @param aad_len length of the aad portion
 * @param tag the nonce to append or prepend to the string
 * @param key the secret shared key
 * @param iv the initialization vector contained in the message
 * @param iv_len the length of the iv
 * @param plaintext pointer to the variable where we store the decrypted text
 * 
 * Decrypt the ciphertext and return its length, the buffer of the plaintext is passed as pointer. 
 * If some error occurs, the message is discarded
 */
int gcm_decrypt(unsigned char *ciphertext, size_t ciphertext_len, 
                unsigned char *aad, size_t aad_len, 
                unsigned char *tag,
                unsigned char *key, unsigned char *iv, 
                size_t iv_len, 
                unsigned char *plaintext) {

    EVP_CIPHER_CTX *ctx;
    int len;
    size_t plaintext_len = 0;

    // Create and initialise the context
    if(!(ctx = EVP_CIPHER_CTX_new())) {
        std::cout<<" Error in creating the context for encryption"<<std::endl;
        handleErrors();
    }
    // Initialise the encryption operation.
    if(1 != EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv)) {
        std::cout<<"Error in Initialising the encryption operation"<<std::endl;
        handleErrors();
    }
    //Provide any AAD data. This can be called zero or more times as required
    if(1 != EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)){
        std::cout<<" Error in providing AAD"<<std::endl;
        handleErrors();
    }


    while ( (plaintext_len < (ciphertext_len - 8)) && ciphertext_len > 8) {    
        //cout << "Entra nel loop?" << endl;
        if(1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, 8)){
            std::cout<<"Error in performing encryption"<<std::endl;
            handleErrors();
        }
        plaintext_len += len;
        ciphertext_len -= len;
    }

    if(1 != EVP_DecryptUpdate(ctx, plaintext + plaintext_len, &len, ciphertext + plaintext_len, ciphertext_len)){
        std::cout<<"Error in performing encryption"<<std::endl;
        handleErrors();
    }
    plaintext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag)){
        std::cout<<"Error in retrieving the tag "<<std::endl;
        handleErrors();
    }

    //Finalize Encryption
    if(1 != EVP_DecryptFinal(ctx, plaintext + plaintext_len, &len)){
        std::cout<<"Error in finalizing encryption"<<std::endl;
        handleErrors();
    }
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}


static DH *get_dh2048(void)
{
    static unsigned char dhp_2048[] = {
        0xCD, 0xC2, 0x8D, 0x71, 0x9F, 0x53, 0x4F, 0x01, 0x09, 0x7B,
        0xE4, 0x38, 0xEA, 0xF9, 0x81, 0x28, 0xFE, 0xBD, 0x6C, 0x0F,
        0x90, 0xCF, 0xF1, 0x5F, 0x3B, 0xA1, 0x97, 0x78, 0x16, 0x6D,
        0x4F, 0xD6, 0x12, 0x03, 0xD9, 0x9A, 0x71, 0x2F, 0xAE, 0x9F,
        0xFC, 0x2C, 0x57, 0xB4, 0x1A, 0x02, 0x2F, 0x85, 0x2B, 0x9E,
        0x27, 0xF5, 0xE5, 0x51, 0x9B, 0xF6, 0x62, 0xCA, 0x49, 0xF8,
        0x0D, 0x95, 0xDD, 0x74, 0xF9, 0xDB, 0x1D, 0xD5, 0x5A, 0xF2,
        0x1D, 0x91, 0x64, 0x76, 0x1C, 0x8B, 0x21, 0xCD, 0x33, 0x7D,
        0xDE, 0x9E, 0x2C, 0xF0, 0x78, 0x73, 0xF0, 0x39, 0x39, 0x25,
        0x58, 0xAD, 0x75, 0x09, 0x7F, 0x60, 0xEC, 0x59, 0xB6, 0x95,
        0x5D, 0xB7, 0x49, 0xE8, 0xF3, 0x4B, 0xB5, 0xEF, 0x3F, 0xFD,
        0xB7, 0x57, 0xB4, 0xFA, 0xB7, 0x52, 0x62, 0x25, 0x93, 0x52,
        0xE2, 0x8E, 0xAA, 0xB2, 0x01, 0xC5, 0x2C, 0x72, 0x34, 0xEC,
        0x16, 0x6B, 0xCC, 0x77, 0x79, 0x76, 0x18, 0x4C, 0x26, 0x13,
        0x19, 0x7D, 0xB5, 0xED, 0xD3, 0xC2, 0x30, 0xE5, 0x01, 0x73,
        0x6A, 0xEE, 0x17, 0x7C, 0x73, 0x52, 0xDB, 0x11, 0xCD, 0x1A,
        0x5A, 0xBB, 0x2A, 0xF5, 0x40, 0xFE, 0x7B, 0x36, 0x9B, 0x34,
        0x3D, 0x61, 0xFA, 0x9C, 0x5B, 0xDB, 0xBF, 0x22, 0xBA, 0x8A,
        0x8A, 0xFB, 0x85, 0x99, 0xDD, 0x77, 0xC8, 0xB9, 0x6A, 0x28,
        0xC1, 0x02, 0x81, 0x55, 0x14, 0x02, 0x10, 0xFF, 0x11, 0xAB,
        0x5D, 0x4B, 0x9C, 0x99, 0xFA, 0x3F, 0xCB, 0xC7, 0xD7, 0xAD,
        0x02, 0x30, 0x23, 0xFD, 0x90, 0x74, 0x2D, 0x11, 0xC3, 0x1F,
        0x17, 0xDF, 0x5C, 0x58, 0x57, 0x7C, 0x0B, 0x4C, 0x9A, 0x56,
        0x21, 0x9C, 0xF9, 0xE6, 0xA6, 0x4D, 0x9E, 0x42, 0x3D, 0x30,
        0xC9, 0xD6, 0x3B, 0x1D, 0x35, 0x78, 0xC1, 0xD7, 0x6E, 0xA5,
        0x6E, 0xA7, 0x6D, 0xA1, 0xE4, 0x13
    };
    static unsigned char dhg_2048[] = {
        0x02
    };
    DH *dh = DH_new();
    BIGNUM *p, *g;

    if (dh == NULL)
        return NULL;
    p = BN_bin2bn(dhp_2048, sizeof(dhp_2048), NULL);
    g = BN_bin2bn(dhg_2048, sizeof(dhg_2048), NULL);
    if (p == NULL || g == NULL
            || !DH_set0_pqg(dh, p, NULL, g)) {
        DH_free(dh);
        BN_free(p);
        BN_free(g);
        return NULL;
    }
    return dh;
}

#endif