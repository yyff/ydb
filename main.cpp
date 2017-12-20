#include "ydb.h"

int main(int argc, char* argv[]) {
    if (argc != 2) {
        ERROR("usage: ./fdb program_name");  
        return -1;
    }

    Debugger debugger(argv[1]);
//    debugger.init(argv[1]);
    debugger.run();

    return 0;
}
