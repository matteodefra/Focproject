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
#include <sstream>
#include <iostream>
#include <fstream>


using namespace std;


#define IV_LEN EVP_CIPHER_iv_length(EVP_aes_128_gcm())
#define NONCE_LEN 16
#define AAD_LEN 12

#define DECRYPTUSERS " \
#/bin/bash \n \
openssl enc -d -aes-256-cbc -in ./AddOn/users.txt.enc -out ./AddOn/users.txt -pbkdf2 -pass file:./AddOn/ChatBox/ChatBox_App_key.pem \
"

#define ENCRYPTUSERS " \
#/bin/bash \n \
openssl enc -aes-256-cbc -in ./AddOn/users.txt -out ./AddOn/users.txt.enc -pbkdf2 -pass file:./AddOn/ChatBox/ChatBox_App_key.pem \
"

#define RMUSERSDECRYPTED " \
#/bin/bash \n \
rm ./AddOn/users.txt \
"

/**
 *  Server side input validation
 */

static char ok_chars[] = "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "1234567890 :";

bool inputSanitization(char *msg) {
    if (strspn(msg,ok_chars) < strlen(msg)) {
        return false;
    }
    return true;
}


/**
 * Util function to increment counter, to avoid replay attacks
 */
void incrementCounter(unsigned char* counter) {
    for (int i=0; i<AAD_LEN; i++) {
        counter[i] += 1;
    }
}

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



/**************** DERIVE SECRET AND ENCRYPT/DECRYPT MESSAGE *************/

/**
 * Function deriveAndEncryptMessage
 * 
 * @param msg the message to be encrypted
 * @param size the size of the corresponding message
 * @param myPublicKey pointer to the diffie hellman public key of the sending party
 * @param partyPublicKey pointer to the diffie hellman public key of the receiver party
 * 
 * This function compute the Diffie Hellman shared secret starting from the given public keys. Then the message is encrypted 
 * using AES in gcm mode, via the function gcm_encrypt(). It returns a pointer to the encrypted ciphertext buffer, if some error 
 * occur it returns a nullptr object
 */ 
unsigned char* deriveAndEncryptMessage(const char *msg, size_t size, EVP_PKEY* myPublicKey, EVP_PKEY* partyPublicKey,unsigned char* counter) {

    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(myPublicKey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    if (1 != EVP_PKEY_derive_set_peer(ctx_drv, partyPublicKey)) {
        handleErrors();
    }
    unsigned char* secret;

    /* Retrieving shared secret’s length */
    cout<<"---------ENCRYPTING-----------"<<endl;
    cout<<"Deriving the shared secret . . ."<<endl;
    size_t secretlen;
    if (1 != EVP_PKEY_derive(ctx_drv, NULL, &secretlen)) {
        handleErrors();
    }
    /* Deriving shared secret */
    secret = (unsigned char*)malloc(secretlen);
    if (secret == NULL) {
        handleErrors();
    }
    if (1 != EVP_PKEY_derive(ctx_drv, secret, &secretlen)) {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx_drv);

    // We need to derive the hash of the shared secret now
    cout<<"Hashing the shared secret . . ."<<endl;
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* digest_ctx;
    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if (!digest) return NULL;
    /* Context allocation */
    digest_ctx = EVP_MD_CTX_new();

    /* Hashing (initialization + single update + finalization */
    EVP_DigestInit(digest_ctx, EVP_sha256());
    EVP_DigestUpdate(digest_ctx, secret, sizeof(secret));
    EVP_DigestFinal(digest_ctx, digest, &digestlen);
    /* Context deallocation */
    EVP_MD_CTX_free(digest_ctx);

    // Taking first 128 bits of the digest
    // Get first 16 bytes of shared secret, to use as key in AES
    unsigned char *key = new unsigned char[16];//(unsigned char*)malloc(16);
    memcpy(key,digest,16);

    free(secret);
    free(digest);

    // Also this section could be moved in an utility function
    unsigned char msg2[size];
    strcpy((char*)msg2,msg);

    unsigned char iv_gcm[IV_LEN];

    RAND_poll();
    int res = RAND_bytes(iv_gcm,IV_LEN);
    if (res != 1) {
        cout << "Core dumped here" << endl;
        // handleErrors();
        return nullptr;
    }

    unsigned char *cphr_buf;
    unsigned char *tag_buf;
    int cphr_len;
    int pt_len = strlen(msg);

    cphr_buf = (unsigned char*)malloc(size);
    if (!cphr_buf) return nullptr;
    tag_buf = (unsigned char*)malloc(16);
    if (!tag_buf) return nullptr;
    cphr_len = gcm_encrypt(msg2,pt_len,counter,AAD_LEN,key,iv_gcm,IV_LEN,cphr_buf,tag_buf);

    auto *buffer = new unsigned char[AAD_LEN/*aad_len*/+pt_len+16/*tag_len*/+IV_LEN/*iv_len*/];

    free(key);

    int pos = 0;

    // copy iv
    memcpy(buffer+pos, iv_gcm, IV_LEN);
    pos += IV_LEN;

    // copy aad
    memcpy((buffer+pos), counter, AAD_LEN);
    pos += AAD_LEN;

    // copy encrypted data
    memcpy((buffer+pos), cphr_buf, cphr_len);
    pos += pt_len;
    free(cphr_buf);

    // copy tag
    memcpy((buffer+pos), tag_buf, 16);
    pos += 16;
    free(tag_buf);

    return buffer;

}


/**
 * Function deriveAndDecryptMessage
 * 
 * @param msg the message to be decrypted
 * @param numOfBytesReceived the size of the corresponding message
 * @param myPublicKey pointer to the diffie hellman public key of the sending party
 * @param partyPublicKey pointer to the diffie hellman public key of the receiver party
 * 
 * This function compute the Diffie Hellman shared secret starting from the given public keys. Then the message is decrypted 
 * using AES in gcm mode, via the function gcm_decrypt(). It returns a pointer to the decrypted plaintext buffer, if some error 
 * occur it returns a nullptr object
 */ 
unsigned char* deriveAndDecryptMessage(char *msg,int numOfBytesReceived,EVP_PKEY* myPublicKey, EVP_PKEY *partyPublicKey,unsigned char* counter) {

    cout<<"---------DECRYPTING-----------"<<endl;
    cout<<"Deriving the shared secret . . ." << endl;

    // Derive the shared secret
    EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(myPublicKey, NULL);
    EVP_PKEY_derive_init(ctx_drv);
    if (1 != EVP_PKEY_derive_set_peer(ctx_drv, partyPublicKey)) {
        handleErrors();
    }
    unsigned char* secret;

    /* Retrieving shared secret’s length */
    size_t secretlen;
    if (1 != EVP_PKEY_derive(ctx_drv, NULL, &secretlen)) {
        handleErrors();
    }
    /* Deriving shared secret */
    secret = (unsigned char*)malloc(secretlen);
    if (secret == NULL) {
        handleErrors();
    }
    if (1 != EVP_PKEY_derive(ctx_drv, secret, &secretlen)) {
        handleErrors();
    }
    EVP_PKEY_CTX_free(ctx_drv);

    // We need to derive the hash of the shared secret now
    cout<<"Hashing the shared secret . . ."<<endl;
    unsigned char* digest;
    unsigned int digestlen;
    EVP_MD_CTX* digest_ctx;
    /* Buffer allocation for the digest */
    digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
    if (!digest) return nullptr;
    /* Context allocation */
    digest_ctx = EVP_MD_CTX_new();

    /* Hashing (initialization + single update + finalization */
    EVP_DigestInit(digest_ctx, EVP_sha256());
    EVP_DigestUpdate(digest_ctx, secret, sizeof(secret));
    EVP_DigestFinal(digest_ctx, digest, &digestlen);
    /* Context deallocation */
    EVP_MD_CTX_free(digest_ctx);

    // Taking first 128 bits of the digest
    // Get first 16 bytes of shared secret, to use as key in AES
    unsigned char *key = (unsigned char*)malloc(16);
    if (!key) return nullptr;
    memcpy(key,digest,16);

    free(secret);
    free(digest);

    int pos = 0;
    // retrieve IV
    unsigned char iv_gcm[IV_LEN];
    memcpy(iv_gcm,msg+pos,IV_LEN);
    pos += IV_LEN;

    // retrieve AAD
    unsigned char AAD[12];
    memcpy(AAD, msg+pos,AAD_LEN);
    pos += AAD_LEN;

    // retrieve encrypted data
    size_t encrypted_len = numOfBytesReceived - 16 - IV_LEN - AAD_LEN;
    unsigned char encryptedData[encrypted_len];
    memcpy(encryptedData,msg+pos,encrypted_len);
    pos += encrypted_len;

    // retrieve tag
    size_t tag_len = 16;
    unsigned char tag[tag_len];
    memcpy(tag, msg+pos, tag_len);
    pos += tag_len;

    unsigned char *plaintext_buffer = new unsigned char[encrypted_len+1];//(unsigned char*)malloc(encrypted_len+1);

    // Decrypt received message with AES-128 bit GCM, store result in plaintext_buffer
    cout<<"AES GCM decryption . . ."<<endl;
    cout<<"-----------------"<<endl;
    
    gcm_decrypt(encryptedData,encrypted_len,counter,AAD_LEN,tag,key,iv_gcm,IV_LEN,plaintext_buffer);

    free(key);

    plaintext_buffer[encrypted_len] = '\0';

    return plaintext_buffer;

}

// ASYMMETRIC ENCRYPTION (Used for DH Public key exchange in the authentication phase)

unsigned char* asymmetric_enc(unsigned char* msg_to_enc, int numBytes, EVP_PKEY* publickey, size_t *length){
    
    cout << "------ASYMMETRIC ENCRYPTION------"<<endl;
    
    unsigned char* encrypted_key = (unsigned char*)malloc(EVP_PKEY_size(publickey));
    if (!encrypted_key) return NULL;
    int encrypted_key_len;

    unsigned char* ciphertext = (unsigned char*)malloc(numBytes + 16);
    if (!ciphertext) return NULL;
    int outlen, cipherlen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    if (!iv) return NULL;
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());
    int ret = EVP_SealInit(ctx,EVP_aes_128_cbc(),&encrypted_key, &encrypted_key_len, iv, &publickey,1);


    if(ret == 0 ){
        cout<<"Error with SealInit during encryption"<<endl;
        return NULL;
    }

    ret = EVP_SealUpdate(ctx,&ciphertext[0],&outlen,msg_to_enc,numBytes);
    if(ret == 0 ){
        ERR_print_errors_fp(stderr);
        cout<<"Error with SealUpdate during encryption"<<endl;
        return NULL;
    }

    cipherlen = outlen;
    ret = EVP_SealFinal(ctx,ciphertext+cipherlen, &outlen);
    if(ret == 0 ){
        cout<<"Error with SealFinal during encryption"<<endl;
        return NULL;
    }

    cipherlen += outlen;
    EVP_CIPHER_CTX_free(ctx);

    auto* buffer = new unsigned char[iv_len + encrypted_key_len + cipherlen];

    //copy iv

    int pos = 0;
    memcpy(buffer+pos,iv,iv_len);
    pos += iv_len;

    //copy key

    memcpy(buffer+pos,encrypted_key,encrypted_key_len);
    pos += encrypted_key_len;

    //copy ciphertext

    memcpy(buffer+pos,ciphertext,cipherlen);

    cout << "Len of the encrypted buffer: " << iv_len+encrypted_key_len+cipherlen << endl;

    // Storing length of the message
    *length = iv_len + encrypted_key_len + cipherlen;

    // Cleaning
    free(iv);
    free(encrypted_key);
    free(ciphertext);

    cout<<"Encrypted message successfully"<<endl;

    return buffer;
}



unsigned char* asymmetric_dec(unsigned char* msg, int msg_len, EVP_PKEY* privatekey,EVP_PKEY* publickey){

    // int msg_len = strlen((char*)msg);
    cout << "------ASYMMETRIC DECRYPTION------"<<endl;
    cout << "Priv key: " << privatekey << endl;

    //Retrieve IV

    unsigned char* iv = (unsigned char*)malloc(EVP_CIPHER_iv_length(EVP_aes_128_cbc()));
    if (!iv) return NULL;
    int iv_len = EVP_CIPHER_iv_length(EVP_aes_128_cbc());

    int pos = 0;
    memcpy(iv,msg,iv_len);
    pos += iv_len;

    cout << "IV len in decryption: " << iv_len << endl;

    //Retrive encrypted_key

    unsigned char* encrypted_key = (unsigned char*)malloc(EVP_PKEY_size(publickey));
    if (!encrypted_key) return NULL;
    int encrypted_key_len = EVP_PKEY_size(privatekey);
    
    memcpy(encrypted_key,msg+pos,encrypted_key_len);
    pos += encrypted_key_len;

    cout << "Encrypted key len in decryption: " << encrypted_key_len << endl;

    //Retrive ciphertext


    int cipherlen = msg_len-iv_len-encrypted_key_len;
    unsigned char* ciphertext = (unsigned char*)malloc(cipherlen);
    if (!ciphertext) return NULL;
    memcpy(ciphertext,msg+pos,cipherlen);

    cout << "Ciphertext len in decryption: " << cipherlen << endl;

    unsigned char* plaintext = (unsigned char*)malloc(cipherlen);
    if (!plaintext) return NULL;
    int outlen, plainlen;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int ret = EVP_OpenInit(ctx,EVP_aes_128_cbc(),encrypted_key,encrypted_key_len,iv,privatekey);
    if(ret == 0){
        cout<<"Error with OpenInit during decryption"<<endl;
        ERR_print_errors_fp(stderr);
        return NULL;
    }

    EVP_OpenUpdate(ctx,plaintext,&outlen,ciphertext,cipherlen);
    plainlen = outlen;
    ret = EVP_OpenFinal(ctx,plaintext+plainlen,&outlen);
    if(ret == 0){
        cout<<"Error with OpenFinal during decryption"<<endl;
        return NULL;
    }
    plainlen += outlen;
    EVP_CIPHER_CTX_free(ctx);

    // Cleaning
    free(iv);
    free(encrypted_key);
    free(ciphertext);

    cout<<"Message decrypted correctly"<<endl;

    return plaintext;
}

#endif
