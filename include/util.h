#include <string>

struct encdecMsg {
    std::string msg;
    unsigned int size;
    encdecMsg() {
        msg = "";
        size = 0;
    }
};

// Create a predefined error message that some problem occured in 
// decrypting message 
#define DECRYPT_ERROR \
    encdecMsg error; \
    error.msg = "error"; \
    error.size = 6; \
    return error; 