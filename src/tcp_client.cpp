#include "../include/tcp_client.h"
#include "../include/client.h"
#include <algorithm> 
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <assert.h>
#include "../include/util.h"

using namespace std;

/**
 *  Help message printed after the command :HELP
 */
void helpMsg(){
    cout<<"********************************************************************"<<endl;
    cout<<"LIST OF AVAILABLE COMMANDS:"<<endl;
    cout<<":LIST -> show the list of all connected clients to the server"<<endl;
    cout<<":REQ <userPeer> -> send a request to talk to the client with username x"<<endl;
    cout<<":LOGIN <password> -> log in to the service"<<endl;
    cout<<":ACCEPT ->  Accept a request-to-talk from a target client"<<endl;
    cout<<":DENY ->  Deny a request-to-talk from a target client"<<endl;
    cout<<"********************************************************************"<<endl;
}

/**
 * This function take a :REG or :LOGIN msg and create and hash for the password
 * return the digest generated
 * bool reg is set at true if it's a reg command, false if it is a login
 */

unsigned char* TcpClient::pswHash(string msg, bool reg){

    cout<<"-----------------"<<endl;
    cout<<"Hashing the password . . ."<<endl;

    char *pointer = strtok((char*)msg.c_str()," ");
    vector<string> credentials; //at.(0) = command | at.(1) = password

    while (pointer != NULL) { //putting the credentials into vector
        credentials.push_back(pointer);
        pointer = strtok(NULL," "); 
    }

    char* c_msg;
    if(reg == false) c_msg =(char*)credentials.at(1).c_str();
        else c_msg =(char*)credentials.at(2).c_str();

    const EVP_MD* hash_function = EVP_sha256();
    unsigned int digest_len;

    unsigned char* digest = new unsigned char[EVP_MD_size(hash_function)];//(unsigned char*)malloc(EVP_MD_size(hash_function));

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx,hash_function);
    EVP_DigestUpdate(ctx,(unsigned char*)c_msg,strlen(c_msg));
    EVP_DigestFinal(ctx,digest,&digest_len);

    EVP_MD_CTX_free(ctx);

    return digest;
}

/**
 *  Check if the command has been writed correctly
 *  Returns 0 if the command has been recognize and not special actions are required
 *  Returns -1 if the command is :HELP
 *  Returns -2 if the command has not been recognized
 *  Returns -3 if the user command is not well formatted
 *  Return   >1 if the command is :LOGIN / :REG (1 login | 2 reg)
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

    if(getAuthSuccess() == false){ //only :USER command can be performed
        if(words.at(0).compare(":USER") == 0 && words.size() == 2 && num_blank == 1){ ///:USER username
            return 0;
        } else {
            return -3;
        }
    } else{
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
        else if(words.at(0).compare(":LOGIN") == 0 && words.size() == 2 && num_blank == 1){ //:LOGIN psw 
            return 1;
        }
        else if(words.at(0).compare(":REG") == 0 && words.size() == 3 && num_blank == 2 && getAdmin()){ ///:REG username psw
            return 2;
        }
        else if(words.at(0).compare(":ACCEPT") == 0 && words.size() == 1 && num_blank == 0){ ///:ACCEPT
            return 0;
        }
         else if(words.at(0).compare(":DENY") == 0 && words.size() == 1 && num_blank == 0){ ///:DENY
            return 0;
        }
        else return -2;
        }
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
 * Callback used in the PEM_readPrivateKey() to check correctness of user password
 */
static int _callback(char *buf, int max_len, int flag, void *ctx)
{   

    char *PASSWD = (char*)ctx;
    size_t len = strlen(PASSWD);

    if(len > max_len)
        return 0;

    memcpy(buf, PASSWD, len+1);
    return len;
}


/**
 * A useful function which uses the static struct of generated p and g DH parameters to create a Diffie Hellman
 * key pair for the client whenever a connecation is established
 */
int TcpClient::generateDHKeypairs() {

    EVP_PKEY* dh_params;
    DH* tmp = get_dh2048();
    dh_params = EVP_PKEY_new();
    // Loading the dh parameters into dhparams structure
    int res = EVP_PKEY_set1_DH(dh_params,tmp);
    DH_free(tmp);


    if (res == 0) {
        finish();
        handleErrors();
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

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(dh_params);

    mykey_pub = my_pubkey;    
    return 1;

}


/**
 * Function called at starting point of client lifecyle. It is used to store the client RSA private key in order to 
 * authenticate with the server in the starting phase
 */
void TcpClient::saveMyKey() {
    string name = getClientName();

    // Save into local variable the client private key.
    // The file is stored into ./AddOn/<client_name>/<client_name>
    string path = "./AddOn/" + name + "/" + name + "RSA.pem"; 

    cout<<"-----------------"<<endl;
    cout << "Path to private RSA key: " << path << endl;
    cout<<"-----------------"<<endl;
 
    FILE *file = fopen(path.c_str(),"rx");
    if (!file) {
        finish();
        handleErrors();
    }

    // Ask client password in order to read the private key
    string val;
    cout << "<ChatBox>: Please type your password to get RSA private key:" << endl;
    getline(cin,val);

    mykey_RSA = PEM_read_PrivateKey(file,NULL,_callback,(void*)val.c_str());
    while (!mykey_RSA) {
        cout << "Wrong password, try again" << endl;
        string psw;
        getline(cin,psw);
        mykey_RSA = PEM_read_PrivateKey(file,NULL,_callback,(void*)psw.c_str());
    }

    fclose(file);
    
    cout<<"-----------------"<<endl;
    cout<<"RSA Key: "<< mykey_RSA<<endl;

    generateDHKeypairs();

    return;
}


/**
 * Allow a client to send a message to the server.
 */
pipe_ret_t TcpClient::sendMsg(const char * msg, size_t size) { 
    pipe_ret_t ret;

    if (getChatting()) {
        // Derive the shared secret

        auto *buffer = deriveAndEncryptMessage(msg,size,mykey_pub,peerKey);

        cout << "Client, dumping the encrypted payload: " << endl;
        BIO_dump_fp(stdout,(char*)buffer,strlen((char*)buffer));

        // Change name accordingly
        int numBytesSent = send(m_sockfd, buffer, 12/*aad_len*/+strlen(msg)+16/*tag_len*/+IV_LEN/*iv_len*/, 0);
        delete buffer;
        if (numBytesSent < 0 ) { // send failed
            ret.success = false;
            ret.msg = strerror(errno);
            return ret;
        }
        if ((uint)numBytesSent < size) { // not all bytes were sent
            ret.success = false;
            string msg = "Not all the bytes were sent to client";
            ret.msg = msg;
            return ret;
        }
        ret.success = true;
        return ret;

    }
 
    else {

        // First message (which must be user) allow us to store the client name and access its private key
        if (strncmp(msg,":USER",5) == 0) {

            char *copy =  new char[size];
            strncpy(copy,msg,size);
            char *pointer = strtok(copy," ");
            pointer = strtok(NULL, " ");
            setClientName(pointer);
            if(strcmp(pointer,"admin") == 0) setAdmin();
            saveMyKey();

            delete copy;

            cout << "Saved key successful" << endl;
            cout<<"-----------------"<<endl;

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
                string msg = "Not all the bytes were sent to client";
                ret.msg = msg;
                return ret;
            }
            ret.success = true;
            return ret;
        }


        auto *buffer = deriveAndEncryptMessage(msg,size,mykey_pub,serverDHKey);

        cout << "Client, dumping the encrypted payload: " << endl;
        BIO_dump_fp(stdout,(char*)buffer,strlen((char*)buffer));
        cout<<"-----------------"<<endl;
        // Change name accordingly
        int numBytesSent = send(m_sockfd, buffer, 12/*aad_len*/+strlen(msg)+16/*tag_len*/+IV_LEN/*iv_len*/, 0);
        delete buffer;
        if (numBytesSent < 0 ) { // send failed
            ret.success = false;
            ret.msg = strerror(errno);
            return ret;
        }
        if ((uint)numBytesSent < size) { // not all bytes were sent
            ret.success = false;
            string msg = "Not all the bytes were sent to client";
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

/**
 * Client send to the server the user command with his username, the server verify if this
 * username is present in his user's list and if it's the authentication can continue and this function will 
 * return true; 
 * 
 * false will be returned if the user is not present.
 * 
 */
bool TcpClient::clientRecognition(){

    //Send client msg with username
    cout<<"<ChatBox>: Welcome, please first enter the user command"<<endl;

    char recv_msg[MAX_PACKET_SIZE];
    int numOfBytesReceived = recv(m_sockfd, recv_msg, MAX_PACKET_SIZE, 0);

    if(numOfBytesReceived < 1) {
        cout<<"Error receiving the username verification"<<endl;
        return false;
    }
    string success_msg = "Client successfully recognize!";
    if(strcmp(recv_msg,(char*)success_msg.c_str()) == 0) {
        cout<<"<ChatBox>: Your username has been recognized by the server"<<endl;
        return true;
    }
        else {
            cout<<"Client not recognized"<<endl;
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

    bool clientAuth = clientRecognition();

    if(clientAuth == false) return false;

    //READ CERT_CA & CRL FROM FILE (known)
    X509* cert_ca;
    X509_CRL* crl_ca;

    FILE* cert_file = fopen("./AddOn/CA/Certificates_CA_cert.pem","rx");
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

    FILE* crl_file = fopen("./AddOn/CA/Certificates_CA_crl.pem","rx");
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
    cout<<"-----------------"<<endl;
    cout<<"Sending the certificate request . . ."<<endl;

    int numBytesSent = send(m_sockfd, (char*)cert_str.c_str(), cert_str.size(), 0);

    if (numBytesSent < 0 ) { // send failed
        cout<<"Error sending the certificate request"<<endl;
        return false;
    }
    if ((uint)numBytesSent < cert_str.size()) { // not all bytes were sent
        cout<<"Error sending the certificate request, not all bytes were sent"<<endl;
        return false;
    }

    cout<<"Waiting for the certificate message . . ."<<endl;

    unsigned char recv_msg[MAX_PACKET_SIZE];
    memset(recv_msg,0,MAX_PACKET_SIZE);
    int numOfBytesReceived = recv(m_sockfd, recv_msg, MAX_PACKET_SIZE, 0);

    if(numOfBytesReceived < 1) {
        cout<<"Error receinving the certificate"<<endl;
        return false;
    }

    cout<<"Certificate message received."<<endl;
    cout<<"-----------------"<<endl;

    cout<<recv_msg;
    cout<<"-----------------"<<endl;

    cout.flush();

    //Get nonce
    unsigned char* nonce =  new unsigned char[NONCE_LEN];
    if (!nonce) return false;

    int pos = 0;

    // retrieve nonce
    memcpy(nonce,recv_msg,NONCE_LEN);
    pos += NONCE_LEN;

    cout << "Nonce extracted: " <<endl;
    BIO_dump_fp(stdout,(char*)nonce,NONCE_LEN);
    cout << "Nonce bytes: " << strlen((char*)nonce) << endl;
    cout<<"-----------------"<<endl;

    //Deserializing the msg

    X509* server_cert = pem_deserialize_certificate((unsigned char*)recv_msg + NONCE_LEN,numOfBytesReceived-NONCE_LEN);

    //Verify Certificate 

    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx,store,server_cert,NULL);
    int ret = X509_verify_cert(ctx);
    if(ret != 1) {
        cout<<"Authentication Error"<<endl;
        return false;
    } else{
        cout<<"<ChatBox>: Certificate Verification Success, server is trusted"<<endl;
        cout<<"-----------------"<<endl;
    }


    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(cert_ca);
    X509_CRL_free(crl_ca);

    //Extract the pubkey from the certificate 

    EVP_PKEY* server_pubkey = X509_get_pubkey(server_cert);
    if(!server_pubkey){
        cout<<"Error retrieving the public key from certificate"<<endl;
        return false;
    }

    free(server_cert);

    cout<<"Server RSA pubkey retrived successfully." << endl;
    serverRSAKey = server_pubkey;


    // Now user need to authenticate himself by digitally sign a message with its own public key
    cout<<"Starting client authentication . . ."<<endl;

    auto* sendMsg = new unsigned char[getClientName().length() + NONCE_LEN];
    int start = 0;
    memcpy(sendMsg + start,getClientName().c_str(),strlen(getClientName().c_str()));
    start += strlen(getClientName().c_str());

    memcpy(sendMsg + start,nonce,NONCE_LEN);
    cout<<"Message to be signed created"<<endl;
    
    unsigned char* signature;
    unsigned int signature_len;

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

    signature =  new unsigned char[EVP_PKEY_size(mykey_RSA)];
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
    ret = EVP_SignUpdate(md_ctx,sendMsg,NONCE_LEN+strlen(getClientName().c_str()));
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

    delete sendMsg;
    EVP_MD_CTX_free(md_ctx);

    cout << "Sending the client message signed . . ."<< endl;
    
    // Server nonce not necessary anymore
    delete nonce;

    int numBytesSent3 = send(m_sockfd, signature, signature_len, 0);
    delete signature;

    if (numBytesSent3 < 0 ) { // send failed
        cout<<"Error sending the signature"<<endl;
        return false;
    }
    if ((uint)numBytesSent3 < signature_len) { // not all bytes were sent
        cout<<"Error sending the signature, not all bytes were sent"<< endl;
        return false;
    }

    //SEND DHpubkey to server

    unsigned char ackMsg[MAX_PACKET_SIZE];
    int ackBytes = recv(m_sockfd, ackMsg, MAX_PACKET_SIZE, 0);
    cout << "Received ACK after signature" << endl;

    cout<<"-----------------"<<endl;
    cout<<"<ChatBox>: The server has successfully verified your signature, authenticated."<<endl;
    cout<<"-----------------"<<endl;

    RAND_poll();

    unsigned char* nonce2 =  new unsigned char[NONCE_LEN];
    if (!nonce2) return false;

    cout<<"Creating a nonce . . ."<<endl;
    int result = RAND_bytes(nonce2,NONCE_LEN);
    if (result != 1) {
        cout << "Error creating nonce(sendCertificate)"<<endl;
        return false;
    }
    cout<<"Nonce created: "<<endl;
    BIO_dump_fp(stdout,(char*)nonce2,NONCE_LEN);
    
    cout<<"Sending the client DH pubkey with nonce. . ."<<endl;

    size_t key_len;
    unsigned char* publicKey = pem_serialize_pubkey(mykey_pub,&key_len);
    unsigned int pubkey_len = strlen((char*)publicKey);
    auto *pubKey_msg = new unsigned char[NONCE_LEN+pubkey_len];

    int position = 0;

    //copy nonce
    memcpy(pubKey_msg+position,nonce2,NONCE_LEN);
    position += NONCE_LEN;

    //copy pubkey
    memcpy((pubKey_msg+position), publicKey, pubkey_len);
    position += pubkey_len;

    cout << "Client DH pubkey message: " <<endl;
    cout << publicKey;
    cout<<"-----------------"<<endl;

    // Encrypt pubkey message with digital envelope
    size_t encrypted_len;

    unsigned char *encrypted = asymmetric_enc(pubKey_msg,NONCE_LEN+pubkey_len,serverRSAKey,&encrypted_len);

    delete pubKey_msg;

    cout << "Length of encrypted buffer after function call: " << encrypted_len << endl;
    cout << "Encrypted message: "<<endl;

    BIO_dump_fp(stdout,(char*)encrypted,strlen((char*)encrypted));
    cout<<"-----------------"<<endl;

    int numBytesSent4 = send(m_sockfd, encrypted, encrypted_len, 0);
    // free(publicKey);
    if (numBytesSent4 < 0) { // send failed
        cout<<"Error sending DH public key"<<endl;
        cout<<"-----------------"<<endl;
        return false;
    }
    if ((uint)numBytesSent4 < encrypted_len) { // not all bytes were sent
        cout<<"Error sending DH public key, not all bytes sent"<<endl;
        return false;
    }

    //Now waits for the DH public key of the server with the nonce
    unsigned char msg[MAX_PACKET_SIZE];
    memset(msg,0,MAX_PACKET_SIZE);
    int numOfBytesReceived2 = recv(m_sockfd, msg, MAX_PACKET_SIZE, 0);

    if(numOfBytesReceived2 < 1) {
        cout<<"Error receiving the DH public key msg"<<endl;
        return false;
    }

    
    cout<<"Server's DH pubkey received . . ."<<endl;


    unsigned char* decrypted_message = asymmetric_dec(msg,numOfBytesReceived2,mykey_RSA,serverRSAKey);

    unsigned char* nonce_extracted = new unsigned char[NONCE_LEN];//(unsigned char*)malloc(NONCE_LEN);

    cout.flush();

    cout<<"-----------------"<<endl;
    cout<<"Server DH public key:"<<endl;
    cout<<decrypted_message+NONCE_LEN<<endl;
    cout<<"-----------------"<<endl;

    //retrieve nonce
    memcpy(nonce_extracted,decrypted_message,NONCE_LEN);

    cout<<"Nonce extracted:"<<endl;
    BIO_dump_fp(stdout,(char*)nonce_extracted,NONCE_LEN);

    if(strcmp((char*)nonce_extracted,(char*)nonce2) != 0) {
        cout<<"Nonces are different"<<endl;
        return false;
    }

    cout<<"Nonces comparison successed"<<endl;
    cout<<"-----------------"<<endl;

    delete nonce_extracted;
    // We have to extract the public key from the buffer
    EVP_PKEY* serverDHPubKey = pem_deserialize_pubkey(decrypted_message+NONCE_LEN,numOfBytesReceived2-NONCE_LEN);
    serverDHKey = serverDHPubKey;

    cout<<"Authentication phase ended, DH keys exchanged successfully"<<endl;
    cout<<"-----------------"<<endl;
    cout<<endl;
    cout<<"<ChatBox> Now you can type commands, use command ':HELP' to show a list of all possible commands."<<endl;

    return true;
}


/*
 * Receive server packets, and notify user
 */
void TcpClient::ReceiveTask() {
    // Whenever client thread starts, the first thing client will do is the authentication
    setAuthSuccess(authenticateServer());

    while(!stop) {
        char msg[MAX_PACKET_SIZE];
        memset(msg,0,MAX_PACKET_SIZE);
        int numOfBytesReceived = recv(m_sockfd, msg, MAX_PACKET_SIZE, 0);

        cout<<"Receinving message from server . . ."<<endl;
        cout<<"-----------------"<<endl;

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

                unsigned char* plaintext_buffer = deriveAndDecryptMessage(msg,numOfBytesReceived,mykey_pub,peerKey);

                // Based on message received, we need to perform some action
                processRequest(plaintext_buffer);
                delete plaintext_buffer;
            }

            else {
                // Also this part could be included in a utility function returning only the decrypted message
                
                
                unsigned char* plaintext_buffer = deriveAndDecryptMessage(msg,numOfBytesReceived,mykey_pub,serverDHKey);

                // Based on message received, we need to perform some action
                processRequest(plaintext_buffer);
                delete plaintext_buffer;
            }
        }
    }
}


// Set peerkey istance inside TcpClient: this is the public key of the peer whenever a req to talk is initialized
void TcpClient::setAndStorePeerKey(unsigned char* key) {
    peerKey = pem_deserialize_pubkey(key,strlen((char*)key));
}

/**
 * Simple process request to get the :KEY message. When the server send this kind of message, the other peer public key can be found
 * in the tail of the message
 */
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
    EVP_PKEY_free(mykey_RSA);
    EVP_PKEY_free(serverDHKey);
    EVP_PKEY_free(serverRSAKey);
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
