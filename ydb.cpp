#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <signal.h>
#include <syscall.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <unistd.h>
#include <errno.h>
#include <string>
#include <vector>
#include <map>
#include <assert.h>
#include "ydb.h"



Debugger::Debugger() {
    // init dict
    dict["run"] = RUN;
    dict["r"] = RUN;
    dict["continue"] = CONTINUE;
    dict["c"] = CONTINUE;

    dict["nextinstr"] = NEXTINSTR;
    dict["ni"] = NEXTINSTR;
    dict["breakpoint"] = BREAKPOINT;
    dict["b"] = BREAKPOINT;
    dict["info"] = INFO;
    dict["i"] = INFO;
    dict["print"] = PRINT;
    dict["p"] = PRINT;
    dict["quit"] = QUIT;
    dict["q"] = QUIT;

}

int Debugger::init(const char *program_file){
    this->program_file = program_file;
    return 0;
}

int Debugger::run() {
    child_pid = fork();
    if (child_pid == 0) {
        if(ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0) {
            ERROR("ptrace(PTRACE_TRACEME, 0, NULL, NULL)\n");
            return -1;
        }
        if(execl(program_file, program_file, 0) < 0) {
            ERROR("call execl failed, program:[%s]\n", program_file);
            return -1;
        }
    }
    LOG("---debugger started---");

    char line_buf[MAX_LINE];
    int wait_status;
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        ERROR("child has exited");
        return -1;
    }

    while (1) {

        

        printf("(ydb)");
        if (fgets(line_buf, MAX_LINE, stdin) == NULL) {
            ERROR("call fgets failed, line:[%s]\n", line_buf);
            return -1;
        }
        if (line_buf[0] != '\n') {
            command.clear();
            if (parse_line(line_buf) < 0) {
                ERROR("call parse_line failed, line[%s]\n", line_buf);
                return -1;
            }

        }

        if (command.size() == 0) {
            LOG("no command");
            continue;
        }

        handle_command();

    }


}

int Debugger::parse_line(char *line_text) {
	assert(line_text);


	int line_len = strlen(line_text);
	if (line_text[line_len - 1] == '\n') {
		line_text[line_len - 1] = '\0';
		--line_len;
	}

	char *p_arg_begin = line_text;
	char *p_arg_end = NULL;
	if ((p_arg_begin = skip_space(p_arg_begin)) == NULL) {
		return 0;
	}

	int num_args = 0;
	while ((p_arg_end = strchr(p_arg_begin, ' ')) != NULL) {
		++num_args;

		*p_arg_end = '\0';
		command.push_back(std::string(p_arg_begin));
		p_arg_begin = p_arg_end + 1;
		if ((p_arg_begin = skip_space(p_arg_begin)) == NULL) {
			return num_args;
		}

	}
    if (p_arg_begin != NULL && p_arg_begin != '\0') {
        command.push_back(std::string(p_arg_begin));
        ++num_args;
    } 
	return num_args;

}


int Debugger::handle_command() {

    if (dict.count(command[0]) == 0) {
        ERROR("no this command:[%s]\n", command[0].c_str());
        return -1;
    }
    int addr;
	switch(dict[command[0]]) {
    case RUN:
        if (continue_run() < 0) {
            ERROR("call continue_run failed");
            return -1;
        }
        break;
	case CONTINUE:
        if (continue_run() < 0) {
            ERROR("call continue_run failed");
            return -1;
        }
		break;
    case NEXTINSTR:
        if (exec_next_instr() < 0) {
            ERROR("call exec_next_instr failed\n");
            return -1;
        }
        break;
    case BREAKPOINT:
        if (command.size() == 1) {
            ERROR("command:[breakpoint] need 1 address");
            return -1;
        }
        sscanf(command[1].c_str(), "%x", &addr);
        if (set_breakpoint((void *)addr) < 0) {
            ERROR("set breakpoint failed\n");
            return -1;
        }
        LOG("breakpoint setted in addr:[0x%x]", addr);
        break;
	case INFO:
        if (command.size() == 1 || command[1] == "regs") {
            if (print_regs() < 0) {
                ERROR("call print_regsfailed\n");
                return -1;
            }
        } else if (command[1] == "breakpoints") {
            std::map<int, unsigned>::iterator it = breakpoints.begin();
            if (it == breakpoints.end()) {
                printf("no breakpoints\n");
            }
            int i = 0;

            while (it != breakpoints.end()) {
                printf("breakpoint [%d]: %x\n", i++, it->first);
                ++it;
            } 
        } else {
            ERROR("error arg:[%s] for command:[info]\n", command[1].c_str());
            return -1;
        }
		break;
	case PRINT:
        if (command.size() == 1) {
            ERROR("missing arg for command:[print]");
            return -1;
        }
        if (sscanf(command[1].c_str(), "%x", &addr) <= 0) {
            ERROR("call sscanf failed\n");
            return -1;
        }
        if (print_var((void *)addr) < 0) {
            ERROR("call print_var failed, addr:[0x%x]\n", addr);
            return -1;
        }
		break;
    case QUIT:
        LOG("---debugger quited---\n");
        exit(0);
        break;
	default:
		printf("no this commond[%s]\n", command[0].c_str());
        return -1;
	}

    return 0;
}

bool Debugger::has_breakpoint() {
    struct user_regs_struct regs;
    assert(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) >= 0);
    //void *addr = (void *)(regs.eip - 1);
    unsigned data = ptrace(PTRACE_PEEKTEXT, child_pid, (void *)(regs.eip - 1), 0);
    return (data & 0xFF) == 0xCC;
}
int Debugger::disable_breakpoint() {
    struct user_regs_struct regs;
    assert(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) >= 0);
    regs.eip--;
    if (breakpoints.count(regs.eip) < 0) {
        ERROR("no existed breakpoint in addr:[%x]", (unsigned)regs.eip);
        return -1;
    }
    assert(ptrace(PTRACE_POKETEXT, child_pid, regs.eip, breakpoints[regs.eip]) >= 0);
    assert(ptrace(PTRACE_SETREGS, child_pid, 0, &regs) >= 0);
    return 0;
}

long Debugger::get_eip() {
    struct user_regs_struct regs;
    assert(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) >= 0);
    return regs.eip;
}


int Debugger::continue_run() {
    assert(ptrace(PTRACE_CONT, child_pid, NULL, NULL) >= 0);
    int wait_status;
    waitpid(child_pid, &wait_status, 0);
    if (WIFEXITED(wait_status)) {
        LOG("chilld has exited!");
        exit(0);
    }
    
    if (has_breakpoint()) {
        LOG("exec until breakpoint in address:[0x%x]", (unsigned)(get_eip() - 1));
        disable_breakpoint();
    }
    return 0;
}
int Debugger::exec_next_instr() {

    if(has_breakpoint()) {
        disable_breakpoint();
    }
    long orig_eip = get_eip();
    long ins;
    ins = ptrace(PTRACE_PEEKTEXT, child_pid, orig_eip, NULL);
    assert(ptrace(PTRACE_SINGLESTEP, child_pid, 0, 0) >= 0);
    int wait_status;
    wait(&wait_status);
    if (WIFEXITED(wait_status)) {
        LOG("chilld has exited!");
        exit(0);
    }

    long cur_eip = get_eip();
    int cycles = std::min((int)(cur_eip - orig_eip), 4);

    char ins_str[1024] = {0};
    sprintf(ins_str, "%x", ins);
    
    char *p_ins = ins_str + strlen(ins_str) - 1;

    printf("execute an instruction:[");
    for(int i = 0; i < cycles; i++) {
        //printf("%02x", *(p_ins + i));
        printf("%c", *(p_ins - 1));
        printf("%c", *(p_ins));
        p_ins -= 2;
    }
    printf("] in address:[0x%x]\n", (unsigned)orig_eip);


    
    return 0;
}

int Debugger::set_breakpoint(void *addr) {
    if (breakpoints.count((int)addr) == 1) {
        return 0;
    }
    unsigned data = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);
    assert(ptrace(PTRACE_POKETEXT, child_pid, addr, data & 0xFFFFFF00 | 0xCC) >= 0);
    breakpoints[(int)addr] = data;
    return 0;
}

int Debugger::print_regs() {
    struct user_regs_struct regs;
    assert(ptrace(PTRACE_GETREGS, child_pid, 0, &regs) >= 0);
    printf("eax\t0x%x\n", (unsigned)regs.eax);
    printf("ebx\t0x%x\n", (unsigned)regs.ebx);
    printf("ecx\t0x%x\n", (unsigned)regs.ecx);
    printf("edx\t0x%x\n", (unsigned)regs.edx);
    printf("esi\t0x%x\n", (unsigned)regs.esi);
    printf("edi\t0x%x\n", (unsigned)regs.edi);
    printf("ebp\t0x%x\n", (unsigned)regs.ebp);
    printf("esp\t0x%x\n", (unsigned)regs.esp);
    printf("eip\t0x%x\n", (unsigned)regs.eip);
    return 0;
}
int Debugger::print_var(void *addr) {
    unsigned data = ptrace(PTRACE_PEEKTEXT, child_pid, addr, 0);
    printf("value of var in addr[0x%x] is: 0x%x\n", (unsigned)addr, data);
    return 0;

}

