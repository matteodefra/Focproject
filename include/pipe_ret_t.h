

#ifndef INTERCOM_PIPE_RETURN_H
#define INTERCOM_PIPE_RETURN_H

#include <string>

struct pipe_ret_t {
    bool success;
    std::string msg;
    pipe_ret_t() {
        success = false;
        msg = "";
    }
};


#endif //INTERCOM_PIPE_RETURN_H
