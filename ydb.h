#ifndef _DEBUGGER_YDB_H_
#define _DEBUGGER_YDB_H_
#include <vector>
#include <string>
#include <map>

#include <stdio.h>
#include <sys/ptrace.h>
#include <sys/reg.h>

#define ERROR( _fmt_, args... ) \
    do{\
        fprintf( stderr, "[%s][%s][%d] " _fmt_"\n", __FILE__, __FUNCTION__, __LINE__, ##args );\
    }while(0)

#define LOG( _fmt_, args... ) \
    do{\
        fprintf( stdout, _fmt_"\n", ##args );\
    }while(0)


class Debugger{

public:
    Debugger(const char *program_file);
    // int init(const char *program_file);
    int run();


private:

    char *skip_space(char *p_str) {
        while (*p_str == ' ') {
            p_str++;
        }
        return *p_str == '\0' ? NULL : p_str;
    } 
    int parse_line(char *line_text);
    int handle_command();

    // command handler
    int continue_run();
    int exec_next_instr();
    int set_breakpoint(void *addr);
    int print_regs();
    int print_var(void *addr);

    // util
    bool has_breakpoint();
    int disable_breakpoint();
    long get_eip();

    static const int MAX_LINE = 1024;
    enum {RUN, CONTINUE, NEXTINSTR, BREAKPOINT, INFO, PRINT, QUIT};
    std::map<std::string, int> dict;
    std::vector<std::string> command;
    std::map<int, unsigned> breakpoints; // key:addr, value:orig data
    bool is_in_breakpoint;
    pid_t child_pid;
    const char *program_file;

};

#endif // _DEBUGGER_YDB_H_
