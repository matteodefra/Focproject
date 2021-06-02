///////////////////////////////////////////////////////////
/////////////////////CLIENT EXAMPLE////////////////////////
///////////////////////////////////////////////////////////

// #ifdef CLIENT_EXAMPLE

#include <iostream>
#include <signal.h>
#include "include/tcp_client.h"

using namespace std;

TcpClient client;


/**
 *  Function to sanitize client input, no symbols allowed.
 * 
 */
char static ok_charsMain[] =        "abcdefghijklmnopqrstuvwxyz"
                         "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                         "1234567890 :";



bool inputSanitizationMain(char *msg) {
    if (strspn(msg,ok_charsMain) < strlen(msg)) {
        return false;
    }
    return true;
}

/**
 * Convert "str" into hex, hexstr will contain the converted string
 */

void stream2hex(const string str, string& hexstr, bool capital = false) 
{
    hexstr.resize(str.size() * 2);
    const size_t a = capital ? 'A' - 1 : 'a' - 1;

    for (size_t i = 0, c = str[0] & 0xFF; i < hexstr.size(); c = str[i / 2] & 0xFF)
    {
        hexstr[i++] = c > 0x9F ? (c / 16 - 9) | a : c / 16 | '0';
        hexstr[i++] = (c & 0xF) > 9 ? (c % 16 - 9) | a : c % 16 | '0';
    }
}

// on sig_exit, close client
void sig_exit(int s)
{
	cout << "Closing client..." << std::endl;
	pipe_ret_t finishRet = client.finish();
	if (finishRet.success) {
		cout << "Client closed." << std::endl;
	} else {
		cout << "Failed to close client." << std::endl;
	}
	exit(0);
}

// observer callback. will be called for every new message received by the server
void onIncomingMsg(const char * msg, size_t size) {
	cout << "<Server>: " << msg << std::endl;
    cout<<endl;
}

// observer callback. will be called when server disconnects
void onDisconnection(const pipe_ret_t & ret) {
	cout << "Server disconnected: " << ret.msg << std::endl;
	cout << "Closing client..." << std::endl;
    pipe_ret_t finishRet = client.finish();
	if (finishRet.success) {
		cout << "Client closed." << std::endl;
	} else {
		cout << "Failed to close client: " << finishRet.msg << std::endl;
	}
}

/**
 *  Substitute the original psw in clear with its hash function 
 *  Return a string of the modified message with the digest included.
 * 
 */

string insertHash(string msg, string digest){
    char *pointer = strtok((char*)msg.c_str()," ");
    vector<string> words; 

    while (pointer != NULL) { //putting every words into vector
         words.push_back(pointer);
        pointer = strtok(NULL," "); 
    }
    string ret;
    if(words.size() == 2) ret = words.at(0) + " " + digest;
        else if (words.size() == 3) ret = words.at(0) + " " + words.at(1) + " " + digest;
    return ret;
}

int main() {
    //register to SIGINT to close client when user press ctrl+c
    signal(SIGINT, sig_exit);
 
    // configure and register observer
    client_observer_t observer;
    observer.wantedIp = "127.0.0.1";
    observer.incoming_packet_func = onIncomingMsg;
    observer.disconnected_func = onDisconnection;
    client.subscribe(observer);
 
    // connect client to an open server
    pipe_ret_t connectRet = client.connectTo("127.0.0.1", 65123);
    if (connectRet.success) {
        cout<<"-----------------"<<endl;
        cout << "Client connected successfully" <<endl;
        cout<<"-----------------"<<endl;
    } else {
        cout<<"-----------------"<<endl;
        cout << "Client failed to connect: " << connectRet.msg <<endl;
        cout<<"-----------------"<<endl;
        return EXIT_FAILURE;
    }
 
    // send messages to server
    while(1)
    {      
        //if(client.getServerAuthenticated() == false) cout<<"We cannot verify the trustness of the server"<<endl;
        string msg;
        getline(cin,msg);   //"hello server\n";
        int valid = 0;
        if(!client.getChatting()) valid = client.checkCommandValidity(msg); //if it is talking to the server, only a set of commands can be performed
        if(valid >= 0){
            if(!client.getChatting()){
                bool input_val = inputSanitizationMain((char*)msg.c_str());
                if (!input_val) {
                    cout<<"<Chatbox>: Error, special characters are not allowed in commands, try again"<<endl;
                    continue;
                }
            }
            if(valid >= 1){
                unsigned char* digest;
                if(valid == 1) digest = client.pswHash(msg,false);
                    else digest = client.pswHash(msg,true);
                string hex_digest;
                stream2hex((char*)digest,hex_digest);
                delete digest;
                cout<<"Password Hash: "<<hex_digest<<endl;
                msg = insertHash(msg,hex_digest);
            }
            if(client.getChatting()){
                cout<<"-----------------"<<endl;
                cout<<"Sending the message to the other client . . ."<<endl;
            } else {
                cout<<"-----------------"<<endl;
                cout<<"Sending the message to the server . . ."<<endl;
            }
            pipe_ret_t sendRet = client.sendMsg(msg.c_str(), msg.size());
            if (!sendRet.success) {
            std::cout << "Failed to send msg: " << sendRet.msg << std::endl;
            break;
            }
        } else if(valid == -2) { cout << "<ChatBox>: This command has not been recognize, try :HELP if you want a list of all the commands."<<endl;}
        else if(valid == -3) { cout << "<ChatBox>: Invalid user command, it must be formatted like ':USER <username>'"<<endl;}
        
        sleep(1);
    }
    return 0;
}
// #endif