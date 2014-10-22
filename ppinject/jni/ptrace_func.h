#ifndef PTRACE_FUNC

#define PTRACE_FUNC
int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size );
int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size );
int ptrace_writestring( pid_t pid, uint8_t *dest, char *str  );
int ptrace_call( pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs );
int ptrace_getregs( pid_t pid, struct pt_regs* regs );
int ptrace_setregs( pid_t pid, struct pt_regs* regs );
int ptrace_continue( pid_t pid );
int ptrace_attach( pid_t pid );
int ptrace_detach( pid_t pid );

#endif