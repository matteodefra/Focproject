#include <string>

struct encdecMsg {
    std::string msg;
    unsigned int size;
    encdecMsg() {
        msg = "";
        size = 0;
    }
};