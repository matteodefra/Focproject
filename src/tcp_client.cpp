#include "../include/tcp_client.h"
#include "../include/client.h"
#include <algorithm> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <assert.h>

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
 * Utility function to handle OPENSSL errors
 */
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}



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
    else if(words.at(0).compare(":ACCEPT") == 0 && words.size() == 1 && num_blank == 0){ ///:ACCEPT
        return 0;
    }
    else if(words.at(0).compare(":USER") == 0 && words.size() == 2 && num_blank == 1){ ///:USER username
        return 0;
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


static int _callback(char *buf, int max_len, int flag, void *ctx)
{   

    cout << "callback called" << endl;

    char *PASSWD = (char*)ctx;
    size_t len = strlen(PASSWD);

    if(len > max_len)
        return 0;

    memcpy(buf, PASSWD, len+1);
    OPENSSL_clear_free(PASSWD,len);
    return len;
}


int TcpClient::generateDHKeypairs() {

    EVP_PKEY* dh_params;
    DH* tmp = get_dh2048();
    dh_params = EVP_PKEY_new();
    // Loading the dh parameters into dhparams structure
    int res = EVP_PKEY_set1_DH(dh_params,tmp);
    DH_free(tmp);

    if (res == 0) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return 0;
    }

    // Generation of the public key
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(dh_params, NULL);
    EVP_PKEY* my_pubkey = NULL;
    EVP_PKEY_keygen_init(ctx);
    if (EVP_PKEY_keygen(ctx, &my_pubkey)!=1) {
        cout << "There was a problem in (p,g) DH parameters generation\nAborting...";
        return 0;
    }

    mykey_pub = my_pubkey;    

}


void TcpClient::saveMyKey() {
    string name = getClientName();

    // Save into local variable the client private key.
    // The file is stored into ./AddOn/<client_name>/<client_name>
    string path = "./AddOn/" + name + "/" + name + "RSA.pem"; 

    cout << "Path to priv RSA key: " << path << endl;
 
    FILE *file = fopen(path.c_str(),"r");
    if (!file) handleErrors();

    // cout << "Input password for RSA private key" << endl;
    // string val;
    // getline(cin,val);

    // mykey_RSA = PEM_read_PrivateKey(file,NULL,_callback,(void*)val.c_str());
    mykey_RSA = PEM_read_PrivateKey(file,NULL,NULL,NULL);
    if (!mykey_RSA) handleErrors(); 

    fclose(file);

    cout<<"mykey_RSA:"<<endl;
    cout << mykey_RSA << endl;

    generateDHKeypairs();

    // string path1 = "./AddOn/" + name + "/" + name + ".pem"; 

    // cout << "Path to priv DH key: " << path1 << endl;
 
    // FILE *file1 = fopen(path1.c_str(),"r");
    // if (!file1) handleErrors();

    // mykey = PEM_read_PrivateKey(file1,NULL,NULL,NULL);
    // if (!mykey) handleErrors(); 

    // fclose(file1);

    // cout<<"mykey:"<<endl;
    // cout << mykey << endl;

    // string path2 = "./AddOn/" + name + "_pub.pem"; 

    // cout << "Path to pub DH key: " << path2 << endl;
 
    // FILE *file2 = fopen(path2.c_str(),"r");
    // if (!file2) handleErrors();

    // mykey_pub = PEM_read_PUBKEY(file2,NULL,NULL,NULL);
    // if (!mykey_pub) handleErrors(); 

    // fclose(file2);

    // cout<<"mykey_pub:"<<endl;
    // cout << mykey_pub << endl;
}


/**
 * Allow a client to send a message to the server. The first setting + encryption call could also be inserted 
 * directly in a utility function, returning the buffer variable since it is the final value we need
 */
pipe_ret_t TcpClient::sendMsg(const char * msg, size_t size) { 
    pipe_ret_t ret;

    if (getChatting()) {
        // Derive the shared secret
        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mykey_pub, NULL);
        EVP_PKEY_derive_init(ctx_drv);
        if (1 != EVP_PKEY_derive_set_peer(ctx_drv, peerKey)) {
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
        unsigned char* digest;
        unsigned int digestlen;
        EVP_MD_CTX* digest_ctx;
        /* Buffer allocation for the digest */
        digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
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
        // for (int i =0; i<16; i++) {
        //     key[i] = digest[i];
        // }
        memcpy(key,digest,16);

        free(secret);
        free(digest);

        // Also this section could be moved in an utility function
        unsigned char msg2[size];
        strcpy((char*)msg2,msg);

        unsigned char iv_gcm[] = "123456780912";
        unsigned char *cphr_buf;
        unsigned char *tag_buf;
        int cphr_len;
        int tag_len;
        int pt_len = strlen(msg);

        cphr_buf = (unsigned char*)malloc(size);
        tag_buf = (unsigned char*)malloc(16);
        cphr_len = gcm_encrypt(msg2,pt_len,iv_gcm,12,key,iv_gcm,12,cphr_buf,tag_buf);

        auto *buffer = new unsigned char[12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/];

        free(key);

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
 
    else {

        // Workaround now to save client name and client public key
        if (strncmp(msg,":USER",5) == 0) {
            cout << "Entra qui" << endl;

            char *copy = (char*) malloc(size);
            strcpy(copy,msg);
            char *pointer = strtok(copy," ");
            pointer = strtok(NULL, " ");
            setClientName(pointer);
            saveMyKey();

            free(copy);

            cout << "Saved key successful" << endl;

            unsigned char msg2[size];
            strcpy((char*)msg2,msg);

            int numBytesSent = send(m_sockfd, msg,size, 0);
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

        cout << "Send client, deriving shared secret" << endl;

        // cout << "My key: " << mykey << endl;
        cout << "Server key: " << serverDHKey << endl; 

        // Derive the shared secret
        EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mykey_pub, NULL);
        EVP_PKEY_derive_init(ctx_drv);
        if (1 != EVP_PKEY_derive_set_peer(ctx_drv, serverDHKey)) {
            cout << "Crash here just at start" << endl;
            handleErrors();
        }
        unsigned char* secret;

        /* Retrieving shared secret’s length */
        size_t secretlen;
        if (1 != EVP_PKEY_derive(ctx_drv, NULL, &secretlen)) {
            cout << "Crash here in the derive" << endl;
            handleErrors();
        }
        /* Deriving shared secret */
        secret = (unsigned char*)malloc(secretlen);
        if (secret == NULL) {
            cout << "Secret is null!" << endl;
            handleErrors();
        }
        if (1 != EVP_PKEY_derive(ctx_drv, secret, &secretlen)) {
            cout << "Crash here in the second derive" << endl;
            handleErrors();
        }
        EVP_PKEY_CTX_free(ctx_drv);

        // We need to derive the hash of the shared secret now
        unsigned char* digest;
        unsigned int digestlen;
        EVP_MD_CTX* digest_ctx;
        /* Buffer allocation for the digest */
        digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
        /* Context allocation */
        digest_ctx = EVP_MD_CTX_new();

        cout << "Before hashing the secret" << endl;

        /* Hashing (initialization + single update + finalization */
        EVP_DigestInit(digest_ctx, EVP_sha256());
        EVP_DigestUpdate(digest_ctx, secret, sizeof(secret));
        EVP_DigestFinal(digest_ctx, digest, &digestlen);
        /* Context deallocation */
        EVP_MD_CTX_free(digest_ctx);

        // Taking first 128 bits of the digest
        // Get first 16 bytes of shared secret, to use as key in AES
        unsigned char *key = (unsigned char*)malloc(16);
        // for (int i =0; i<16; i++) {
        //     key[i] = digest[i];
        // }
        memcpy(key,digest,16);

        free(secret);
        free(digest);

        cout << "Diffie Hellman secret: " << key << endl;

        // Also this section could be moved in an utility function
        unsigned char msg2[size];
        strcpy((char*)msg2,msg);

        // unsigned char key_gcm[] = "1234567890123456";
        unsigned char iv_gcm[] = "123456780912";
        unsigned char *cphr_buf;
        unsigned char *tag_buf;
        int cphr_len;
        int tag_len;
        int pt_len = strlen(msg);

        cphr_buf = (unsigned char*)malloc(size);
        tag_buf = (unsigned char*)malloc(16);
        cphr_len = gcm_encrypt(msg2,pt_len,iv_gcm,12,key,iv_gcm,12,cphr_buf,tag_buf);

        auto *buffer = new unsigned char[12/*aad_len*/+pt_len+16/*tag_len*/+12/*iv_len*/];

        free(key);

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

bool TcpClient::clientAuthentication(){

    //Send client msg with username
    cout<<"Welcome, please enter your username:"<<endl;
    // size_t num_blank = 1; 

    // string username = "tommy"; //dovrebbe leggerlo da input
    // /*
    // while(num_blank != 0){
    //     getline(cin,username); 
    //     num_blank = count(username.begin(), username.end(),' '); //count blankets
    //     if(num_blank != 0) { 
    //         cout<<"Username can not contain blankets, please retry"<<endl;
    //     }
    // }*/
      
    // string username_msg = ":USER " + username;
    // cout<<"USERNAME MSG"<<endl;
    // cout<<username_msg<<endl;

    // int numBytesSent = send(m_sockfd, (char*)username_msg.c_str(), username_msg.size(), 0);

    // if (numBytesSent < 0 ) { // send failed
    //     cout<<"Error sending the username"<<endl;
    //     return false;
    // }
    // if ((uint)numBytesSent < username_msg.size()) { // not all bytes were sent
    //     cout<<"Error sending the username, not all bytes were sent"<<endl;
    //     return false;
    // }

    char recv_msg[MAX_PACKET_SIZE];
    int numOfBytesReceived = recv(m_sockfd, recv_msg, MAX_PACKET_SIZE, 0);

    if(numOfBytesReceived < 1) {
        cout<<"Error receinving the username verification"<<endl;
        return false;
    }
    string success_msg = "Client successfully recognize!";
    if(strcmp(recv_msg,(char*)success_msg.c_str()) == 0) {
        cout<<"CLIENT RICONOSCIUTO"<<endl;
        return true;
    }
        else {
            cout<<"CLIENT NOT RECOGNIZED!"<<endl;
            return false;
        }


}


/**
 * First function that need to be implemented: the starting client,
 * after connection, will first authenticate, with a public key preinstalled 
 * on the server. The private key will be inside each client protected by a
 * password. After the autenthication, if everything went well client and 
 * server will negotiate a session key to use for their communication
 */
bool TcpClient::authenticateServer() {


    //Client Authentication

    bool clientAuth = clientAuthentication();

    if(clientAuth == false) return false;

    //READ CERT_CA & CRL FROM FILE (known)
    X509* cert_ca;
    X509_CRL* crl_ca;

    FILE* cert_file = fopen("./AddOn/CA/Certificates_CA_cert.pem","r");
    if(!cert_file) { 
        cout<<"Error opening the CA certificate file"<<endl;
        return false;
    }
    cert_ca = PEM_read_X509(cert_file,NULL,NULL,NULL);
    if(!cert_ca) {
        cout<<"Error reading from the CA certificate file"<<endl;
        return false;
    }
    fclose(cert_file);

    FILE* crl_file = fopen("./AddOn/CA/Certificates_CA_crl.pem","r");
    if(!crl_file){
        cout<<"Error opening the CA CRL file"<<endl;
        return false;
    }
    crl_ca = PEM_read_X509_CRL(crl_file,NULL,NULL,NULL);
    if(!crl_ca){
        cout<<"Error reading the CA CRL file"<<endl;
        return false;
    }
    fclose(crl_file);

    
    //Create Store

    X509_STORE* store = X509_STORE_new();
    X509_STORE_add_cert(store,cert_ca);
    X509_STORE_add_crl(store,crl_ca);
    X509_STORE_set_flags(store,X509_V_FLAG_CRL_CHECK);


    //Receive Certificate
    string cert_str = ":CERT";

    cout<<"MESSAGGIO INVIATO:"<<endl;
    cout<<cert_str<<endl;

    int numBytesSent = send(m_sockfd, (char*)cert_str.c_str(), cert_str.size(), 0);

    if (numBytesSent < 0 ) { // send failed
        cout<<"Error sending the certificate request"<<endl;
        return false;
    }
    if ((uint)numBytesSent < cert_str.size()) { // not all bytes were sent
        cout<<"Error sending the certificate request, not all bytes were sent"<<endl;
        return false;
    }

    //TODO: Need to receive the exact bytes of the certificate!! Two consecutive recv
    unsigned char recv_msg[MAX_PACKET_SIZE];
    memset(recv_msg,0,MAX_PACKET_SIZE);
    int numOfBytesReceived = recv(m_sockfd, recv_msg, MAX_PACKET_SIZE, 0);

    if(numOfBytesReceived < 1) {
        cout<<"Error receinving the certificate"<<endl;
        return false;
    }

    cout<<recv_msg<<endl;

    //Deserializing the msg

    X509* server_cert = pem_deserialize_certificate(recv_msg,strlen((char*)recv_msg));

    //Verify Certificate 

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx,store,server_cert,NULL);
    int ret = X509_verify_cert(ctx);
    if(ret != 1) {
        cout<<"Authentication Error"<<endl;
        return false;
    } else{
        cout<<"Certificate Verification Success"<<endl;
    }


    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);

    //Extract the pubkey from the certificate 

    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    if(!server_pubkey){
        cout<<"Error retrieving the public key from certificate"<<endl;
        return false;
    }

    serverRSAKey = server_pubkey;


    // Now user need to authenticate himself by digitally sign a message with its own public key
    string toSend = getClientName() + " user";
    char *sendMsg = (char*)toSend.c_str(); 

    unsigned char* signature;
    unsigned int signature_len;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    signature = (unsigned char*)malloc(EVP_PKEY_size(mykey_RSA));
    if (!signature) {
        cout << "ERROR!" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    ret = EVP_SignInit(md_ctx,EVP_sha256());
    if (ret == 0) {
        cout << "ERROR!" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }
    ret = EVP_SignUpdate(md_ctx,(unsigned char*)sendMsg,strlen(sendMsg));
    if (ret == 0) {
        cout << "ERROR!" << endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    ret = EVP_SignFinal(md_ctx,signature,&signature_len,mykey_RSA);
    if (ret == 0) {
        cout << "ERROR!" << endl;
        ERR_print_errors_fp(stderr);
        return false;   
    }

    EVP_MD_CTX_free(md_ctx);
    // EVP_PKEY_free(mykey);

    cout << "Client signature: " << signature << endl;

    cout << "Client signature len: " << signature_len << endl;

    int numBytesSent3 = send(m_sockfd, signature, signature_len, 0);

    if (numBytesSent3 < 0 ) { // send failed
        cout<<"Error sending the signature"<<endl;
        return false;
    }
    if ((uint)numBytesSent3 < signature_len) { // not all bytes were sent
        cout<<"Error sending the signature, not all bytes were sent"<< endl;
        return false;
    }


    // Send public key, authentication using certificates
    // Then symmetric session key negotiation via elliptic curve diffie hellman
    // Now user wait for server public key
    char msg[MAX_PACKET_SIZE];
    memset(msg,0,MAX_PACKET_SIZE);
    int numOfBytesReceived2 = recv(m_sockfd, msg, MAX_PACKET_SIZE, 0);

    cout << "Client, DH pubkey received is: " << msg << endl;

    if(numOfBytesReceived2 < 1) {
        pipe_ret_t ret;
        ret.success = false;
        stop = true;
        if (numOfBytesReceived2 == 0) { //server closed connection
            ret.msg = "Server closed connection";
        } else {
            ret.msg = strerror(errno);
        }
        publishServerDisconnected(ret);
        finish();
    }

    unsigned char msg2[numOfBytesReceived2];
    strcpy((char*)msg2,msg);

    cout << "Server DH public key here: " << msg2 << endl; 

    // We have to extract the public key from the buffer
    EVP_PKEY* serverDHPubKey = pem_deserialize_pubkey(msg2,numOfBytesReceived2);
    serverDHKey = serverDHPubKey;


    //SEND DHpubkey to server

    size_t key_len;
    unsigned char* publicKey = pem_serialize_pubkey(mykey_pub,&key_len);

    cout << "Client DH public key here: " << publicKey << endl;

    cout<<"DH PUBKEY:"<<endl;
    cout<<publicKey<<endl;
    int numBytesSent4 = send(m_sockfd, publicKey, key_len, 0);
    if (numBytesSent4 < 0) { // send failed
        cout<<"Error sending DH public key"<<endl;
        return false;
    }
    if ((uint)numBytesSent4 < key_len) { // not all bytes were sent
        cout<<"Error sending DH public key, not all bytes sent"<<endl;
        return false;
    }

    return true;
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
    setServerAuthenticated(authenticateServer());

    while(!stop) {
        char msg[MAX_PACKET_SIZE];
        memset(msg,0,MAX_PACKET_SIZE);
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

            if (getChatting()) {
                // Derive the shared secret
                EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mykey_pub, NULL);
                EVP_PKEY_derive_init(ctx_drv);
                if (1 != EVP_PKEY_derive_set_peer(ctx_drv, peerKey)) {
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
                unsigned char* digest;
                unsigned int digestlen;
                EVP_MD_CTX* digest_ctx;
                /* Buffer allocation for the digest */
                digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
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
                // for (int i =0; i<16; i++) {
                //     key[i] = digest[i];
                // }
                memcpy(key,digest,16);

                free(secret);
                free(digest);

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
                int decrypted_len = gcm_decrypt(encryptedData,encrypted_len,AAD,12,tag,key,iv_gcm,12,plaintext_buffer);
                plaintext_buffer[encrypted_len] = '\0';

                free(key);
                
                cout << "Client, message decrypted: " << plaintext_buffer << endl;

                // Based on message received, we need to perform some action
                processRequest(plaintext_buffer);
                free(plaintext_buffer);
            }

            else {
                // Also this part could be included in a utility function returning only the decrypted message

                cout << "Client: start decryption process..." << endl;

                // Derive the shared secret
                EVP_PKEY_CTX* ctx_drv = EVP_PKEY_CTX_new(mykey_pub, NULL);
                EVP_PKEY_derive_init(ctx_drv);
                if (1 != EVP_PKEY_derive_set_peer(ctx_drv, serverDHKey)) {
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
                unsigned char* digest;
                unsigned int digestlen;
                EVP_MD_CTX* digest_ctx;
                /* Buffer allocation for the digest */
                digest = (unsigned char*)malloc(EVP_MD_size(EVP_sha256()));
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
                // for (int i =0; i<16; i++) {
                //     key[i] = digest[i];
                // }
                memcpy(key,digest,16);

                free(secret);
                free(digest);

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
                int decrypted_len = gcm_decrypt(encryptedData,encrypted_len,AAD,12,tag,key,iv_gcm,12,plaintext_buffer);
                plaintext_buffer[encrypted_len] = '\0';
                
                cout << "Client, message decrypted: " << plaintext_buffer << endl;

                // Based on message received, we need to perform some action
                processRequest(plaintext_buffer);
                free(plaintext_buffer);
            }
        }
    }
}


void TcpClient::setAndStorePeerKey(unsigned char* key) {
    // Set peerkey istance inside TcpClient
    peerKey = pem_deserialize_pubkey(key,strlen((char*)key));

    // Save key into file. The peer public key is saved into folder
    // AddOn/<client_name>/peer.pem
    // string path = "./AddOn/" + clientName + "/peer.pem";
    // FILE *file = fopen(path.c_str(),"w");
    // if (!file) {
    //     handleErrors();
    // }

    // int res = PEM_write_PUBKEY(file,peerKey);
    // if (!res) {
    //     handleErrors();
    // }
}

void TcpClient::processRequest(unsigned char* plaintext_buffer) {
    char *message = (char*)plaintext_buffer;

    if (strncmp(message,":KEY",4) == 0) {
        setChatting();

        // Move pointer to key
        unsigned char *key = (unsigned char*)plaintext_buffer + 5;

        // When a key message arrives, save the key into tcpclient object
        setAndStorePeerKey(key);
    }
    else {
        publishServerMsg(message,strlen(message));
    }
}

/**
 * Close thread instance and socket
 */
pipe_ret_t TcpClient::finish(){
    stop = true;
    terminateReceiveThread();
    // OPENSSL_free(mykey);
    OPENSSL_free(serverDHKey);
    OPENSSL_free(serverRSAKey);
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
