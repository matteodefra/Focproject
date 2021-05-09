#include "../include/tcp_client.h"
#include "../include/client.h"
#include <algorithm> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

/**
 *  Help message printed after the command :HELP
 */

void helpMsg(){
    cout<<"********************************************************************"<<endl;
    cout<<"LIST OF AVAILABLE COMMANDS:"<<endl;
    cout<<":LIST -> show the list of all connected clients to the server"<<endl;
    cout<<":REQ x -> send a request to talk to the client with username x"<<endl;
    cout<<":LOGIN -> log in to the service"<<endl;
    cout<<"********************************************************************"<<endl;
}

/**
 * This function take a :REG or :LOGIN msg and create and hash for the password
 * return the digest generated
 */

unsigned char* TcpClient::pswHash(string msg){

    char *pointer = strtok((char*)msg.c_str()," ");
    vector<string> credentials; //at.() = username | at.(1) = password
    int counter = 0; //used to skip :LOGIN/:REG part

    while (pointer != NULL) { //putting the credentials into vector
        if(counter != 0) credentials.push_back(pointer);
        pointer = strtok(NULL," "); 
        counter++;
    }

    char* c_msg =(char*)credentials.at(1).c_str();
    const EVP_MD* hash_function = EVP_sha256();
    unsigned int digest_len;

    unsigned char* digest = (unsigned char*)malloc(EVP_MD_size(hash_function));

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx,hash_function);
    EVP_DigestUpdate(ctx,(unsigned char*)c_msg,strlen(c_msg));
    EVP_DigestFinal(ctx,digest,&digest_len);

    cout<<"HASH:"<<endl;
    BIO_dump_fp(stdout,(char*)digest,strlen((char*)digest));

    EVP_MD_CTX_free(ctx);

    return digest;
}

/**
 *  Check if the command has been writed correctly
 *  Returns 0 if the command has been recognize and not special actions are required
 *  Returns -1 if the command is :HELP
 *  Returns -2 if the command has not been recognized
 *  Return   1 if the command is :LOGIN / :REG (require hashing of the psw)
 * 
 */

int TcpClient::checkCommandValidity(string msg) { 

    size_t num_blank = count(msg.begin(), msg.end(),' '); //count blankets

    char *pointer = strtok((char*)msg.c_str()," ");
    vector<string> words; 

    while (pointer != NULL) {  //insert all the words of a command in this vector
        words.push_back(pointer);
        pointer = strtok(NULL," ");
    }
 
    if(words.size() == 0) return -2;

    if(words.at(0).compare(":LIST")==0 && words.size() == 1 && num_blank == 0) { 
        return 0;
    }
    else if(words.at(0).compare(":HELP")==0 && words.size() == 1 && num_blank == 0) {
        helpMsg(); 
        return -1;
    } 
    else if(words.at(0).compare(":REQ") == 0 && words.size() == 2 && num_blank == 1){ //:REQ username
        return 0;
    }
    else if(words.at(0).compare(":LOGIN") == 0 && words.size() == 3 && num_blank == 2){ //:LOGIN username psw 
        return 1;
    }
    else if(words.at(0).compare(":REG") == 0 && words.size() == 3 && num_blank == 2){ ///:REG username psw
        return 1;
    }
     else return -2;
}
 

// Connect the client to the server by passing the IP address of the server and the port
// Returns a pipe_ret_t instance
pipe_ret_t TcpClient::connectTo(const std::string & address, int port) {
    m_sockfd = 0;
    pipe_ret_t ret;

    m_sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (m_sockfd == -1) { //socket failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }

    int inetSuccess = inet_aton(address.c_str(), &m_server.sin_addr); //returns non-zero if the address is a valid one, 
                                                                      //and it returns zero if the address is invalid.

    if(!inetSuccess) { // inet_addr failed to parse address
        // if hostname is not in IP strings and dots format, try resolve it
        struct hostent *host;
        struct in_addr **addrList;
        if ( (host = gethostbyname( address.c_str() ) ) == NULL){
            ret.success = false;
            ret.msg = "Failed to resolve hostname";
            return ret;
        }
        addrList = (struct in_addr **) host->h_addr_list;
        m_server.sin_addr = *addrList[0];
    }

    m_server.sin_family = AF_INET;
    m_server.sin_port = htons( port );

    int connectRet = connect(m_sockfd , (struct sockaddr *)&m_server , sizeof(m_server));

    if (connectRet == -1) { //connect failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }

    m_receiveTask = new std::thread(&TcpClient::ReceiveTask, this);
    ret.success = true;
    return ret;
}

/**
 * Utility function to handle OPENSSL errors
 */
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

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
    int ciphertext_len = 0;

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
 * Allow a client to send a message to the server. The first setting + encryption call could also be inserted 
 * directly in a utility function, returning the buffer variable since it is the final value we need
 */
pipe_ret_t TcpClient::sendMsg(const char * msg, size_t size) { 
    pipe_ret_t ret;

    // Also this section could be moved in an utility function
    unsigned char msg2[size];
    strcpy((char*)msg2,msg);

    unsigned char key_gcm[] = "1234567890123456";
    unsigned char iv_gcm[] = "123456780912";
    unsigned char *cphr_buf;
    unsigned char *tag_buf;
    int cphr_len;
    int tag_len;
    int pt_len = strlen(msg);

    cphr_buf = (unsigned char*)malloc(size);
    tag_buf = (unsigned char*)malloc(16);
    cphr_len = gcm_encrypt(msg2,pt_len,iv_gcm,12,key_gcm,iv_gcm,12,cphr_buf,tag_buf);

    auto *buffer = new unsigned char[12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/];

    int pos = 0;
  
    // copy iv
    memcpy(buffer+pos, iv_gcm, 12);
    pos += 12;
    // delete [] iv_gcm;

    // copy aad
    memcpy((buffer+pos), iv_gcm, 12);
    pos += 12;

    // copy encrypted data
    memcpy((buffer+pos), cphr_buf, cphr_len);
    pos += pt_len;
    delete[] cphr_buf;

    // copy tag
    memcpy((buffer+pos), tag_buf, 16);
    pos += 16;
    delete [] tag_buf;

    cout << "Client, dumping the encrypted payload: " << endl;
    BIO_dump_fp(stdout,(char*)buffer,strlen((char*)buffer));
    cout << "Total buffer dimension: "<< strlen((char*)buffer) << endl;

    // Change name accordingly
    int numBytesSent = send(m_sockfd, buffer, 12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/, 0);
    if (numBytesSent < 0 ) { // send failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    if ((uint)numBytesSent < size) { // not all bytes were sent
        ret.success = false;
        char msg[100];
        sprintf(msg, "Only %d bytes out of %lu was sent to client", numBytesSent, size);
        ret.msg = msg;
        return ret;
    }
    ret.success = true;
    return ret;
}

void TcpClient::subscribe(const client_observer_t & observer) {
    m_subscribers.push_back(observer);
}

void TcpClient::unsubscribeAll() {
    m_subscribers.clear();
}

/*
 * Publish incoming client message to observer.
 * Observers get only messages that originated
 * from clients with IP address identical to
 * the specific observer requested IP
 */
void TcpClient::publishServerMsg(const char * msg, size_t msgSize) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].incoming_packet_func != NULL) {
            (*m_subscribers[i].incoming_packet_func)(msg, msgSize);
        }
    }
}

/*
 * Publish client disconnection to observer.
 * Observers get only notify about clients
 * with IP address identical to the specific
 * observer requested IP
 */
void TcpClient::publishServerDisconnected(const pipe_ret_t & ret) {
    for (uint i=0; i<m_subscribers.size(); i++) {
        if (m_subscribers[i].disconnected_func != NULL) {
            (*m_subscribers[i].disconnected_func)(ret);
        }
    }
}

/**
 * First function that need to be implemented: the starting client,
 * after connection, will first authenticate, with a public key preinstalled 
 * on the server. The private key will be inside each client protected by a
 * password. After the autenthication, if everything went well client and 
 * server will negotiate a session key to use for their communication
 */
void TcpClient::authenticateThroughServer() {
    // Send public key, authentication using certificates
    // Then symmetric session key negotiation via elliptic curve diffie hellman
    return;
}

/**
 * This function will ask server for all connected clients.
 * Need to implement secure communication through symmetric key
 */
void TcpClient::displayAllClients() {
    return;
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
    int plaintext_len = 0;

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

    // Needed for comparison between size_t and integer
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


/*
 * Receive server packets, and notify user
 */
void TcpClient::ReceiveTask() {

    // Whenever client thread starts, the first thing client will do is the authentication
    authenticateThroughServer();

    while(!stop) {
        char msg[MAX_PACKET_SIZE];
        int numOfBytesReceived = recv(m_sockfd, msg, MAX_PACKET_SIZE, 0);

        if(numOfBytesReceived < 1) {
            pipe_ret_t ret;
            ret.success = false;
            stop = true;
            if (numOfBytesReceived == 0) { //server closed connection
                ret.msg = "Server closed connection";
            } else {
                ret.msg = strerror(errno);
            }
            publishServerDisconnected(ret);
            finish();
            break;
        } else {
            // Also this part could be included in a utility function returning only the decrypted message

            cout << "Client: start decryption process..." << endl;

            unsigned char key_gcm[] = "1234567890123456";

            int pos = 0;
            // retrieve IV
            unsigned char iv_gcm[12];
            memcpy(iv_gcm,msg+pos,12);
            pos += 12;

            // retrieve AAD
            unsigned char AAD[12];
            memcpy(AAD, msg+pos,12);
            pos += 12;

            // retrieve encrypted data
            size_t encrypted_len = numOfBytesReceived - 16 - 12 - 12;
            unsigned char encryptedData[encrypted_len];
            memcpy(encryptedData,msg+pos,encrypted_len);
            pos += encrypted_len;

            // retrieve tag
            size_t tag_len = 16;
            unsigned char tag[tag_len];
            memcpy(tag, msg+pos, tag_len);
            pos += tag_len;

            unsigned char *plaintext_buffer = (unsigned char*)malloc(encrypted_len+1);

            // Decrypt received message with AES-128 bit GCM
            int decrypted_len = gcm_decrypt(encryptedData,encrypted_len,AAD,12,tag,key_gcm,iv_gcm,12,plaintext_buffer);
            plaintext_buffer[encrypted_len] = '\0';
            
            cout << "Client, message decrypted: " << plaintext_buffer << endl;

            // Based on message received, we need to perform some action
            publishServerMsg((char*)plaintext_buffer,decrypted_len);
            free(plaintext_buffer);
        }
    }
}

/**
 * Close thread instance and socket
 */
pipe_ret_t TcpClient::finish(){
    stop = true;
    terminateReceiveThread();
    pipe_ret_t ret;
    if (close(m_sockfd) == -1) { // close failed
        ret.success = false;
        ret.msg = strerror(errno);
        return ret;
    }
    ret.success = true;
    return ret;
}

/**
 * Close thread instance
 */
void TcpClient::terminateReceiveThread() {
    if (m_receiveTask != nullptr) {
        m_receiveTask->detach();
        delete m_receiveTask;
        m_receiveTask = nullptr;
    }
}

TcpClient::~TcpClient() {
    terminateReceiveThread();
}
