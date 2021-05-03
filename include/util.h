#include <string>

struct encdecMsg {
    std::string msg;
    unsigned int msg_size;
    std::string iv; // può andare come stringa? perchè senno potremmo lasciarlo unsigned char *
    unsigned int iv_size;
    encdecMsg() {
        msg = "";
        msg_size = 0;
        iv = "";
        iv_size = 0;
    }
};