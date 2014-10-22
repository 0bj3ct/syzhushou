#include <asm/ptrace.h>
#include <sys/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

#define CPSR_T_MASK		( 1u << 5 )

int ptrace_readdata( pid_t pid,  uint8_t *src, uint8_t *buf, size_t size )
{
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = buf;

	for ( i = 0; i < j; i ++ )
	{
		d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
		memcpy( laddr, d.chars, 4 );
		src += 4;
		laddr += 4;
	}

	if ( remain > 0 )
	{
		d.val = ptrace( PTRACE_PEEKTEXT, pid, src, 0 );
		memcpy( laddr, d.chars, remain );
	}

	return 0;

}

int ptrace_writedata( pid_t pid, uint8_t *dest, uint8_t *data, size_t size )
{
	uint32_t i, j, remain;
	uint8_t *laddr;

	union u {
		long val;
		char chars[sizeof(long)];
	} d;

	j = size / 4;
	remain = size % 4;

	laddr = data;

	for ( i = 0; i < j; i ++ )
	{
		memcpy( d.chars, laddr, 4 );
		ptrace( PTRACE_POKETEXT, pid, dest, d.val );

		dest  += 4;
		laddr += 4;
	}

	if ( remain > 0 )
	{
		d.val = ptrace( PTRACE_PEEKTEXT, pid, dest, 0 );
		for ( i = 0; i < remain; i ++ )
		{
			d.chars[i] = *laddr ++;
		}

		ptrace( PTRACE_POKETEXT, pid, dest, d.val );

	}

	return 0;
}


int ptrace_writestring( pid_t pid, uint8_t *dest, char *str  )
{
	return ptrace_writedata( pid, dest, str, strlen(str)+1 );
}

int ptrace_call( pid_t pid, uint32_t addr, long *params, uint32_t num_params, struct pt_regs* regs )
{
	uint32_t i;

	for ( i = 0; i < num_params && i < 4; i ++ )
	{
		regs->uregs[i] = params[i];
	}

	//
	// push remained params onto stack
	//
	if ( i < num_params )
	{
		regs->ARM_sp -= (num_params - i) * sizeof(long) ;
		ptrace_writedata( pid, (void *)regs->ARM_sp, (uint8_t *)&params[i], (num_params - i) * sizeof(long) );
	}

	regs->ARM_pc = addr;
	if ( regs->ARM_pc & 1 )
	{
		/* thumb */
		regs->ARM_pc &= (~1u);
		regs->ARM_cpsr |= CPSR_T_MASK;
	}
	else
	{
		/* arm */
		regs->ARM_cpsr &= ~CPSR_T_MASK;
	}


	regs->ARM_lr = 0;	

	if ( ptrace_setregs( pid, regs ) == -1 
		|| ptrace_continue( pid ) == -1 )
	{
		return -1;
	}


	waitpid( pid, NULL, 0 );

	return 0;
}



int ptrace_getregs( pid_t pid, struct pt_regs* regs )
{
	if ( ptrace( PTRACE_GETREGS, pid, NULL, regs ) < 0 )
	{
		perror( "ptrace_getregs: Can not get register values" );
		return -1;
	}

	return 0;
}

int ptrace_setregs( pid_t pid, struct pt_regs* regs )
{
	if ( ptrace( PTRACE_SETREGS, pid, NULL, regs ) < 0 )
	{
		perror( "ptrace_setregs: Can not set register values" );
		return -1;
	}

	return 0;
}




int ptrace_continue( pid_t pid )
{
	if ( ptrace( PTRACE_CONT, pid, NULL, 0 ) < 0 )
	{
		perror( "ptrace_cont" );
		return -1;
	}

	return 0;
}

int ptrace_attach( pid_t pid )
{
	struct pt_regs regs;
	if ( ptrace( PTRACE_ATTACH, pid, NULL, 0  ) < 0 )
	{
		perror( "ptrace_attach" );
		return -1;
	}

	waitpid( pid, NULL, WUNTRACED );

	//DEBUG_PRINT("attached\n");

	ptrace_getregs(pid,&regs);
	printf("[++++] first pc:%x\n",regs.ARM_pc);
	printf("[++++] first lr:%x\n",regs.ARM_lr);
	printf("[++++] first cpsr:%x\n",regs.ARM_cpsr);
	if ( ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0 )
	{
		perror( "ptrace_syscall" );
		return -1;
	}
	waitpid( pid, NULL, WUNTRACED );

	ptrace_getregs(pid,&regs);
	printf("[++++] second pc:%x\n",regs.ARM_pc);
	printf("[++++] second lr:%x\n",regs.ARM_lr);
	printf("[++++] second cpsr:%x\n",regs.ARM_cpsr);
	if ( ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0 )
	{
		perror( "ptrace_syscall" );
		return -1;
	}
	waitpid( pid, NULL, WUNTRACED );

	ptrace_getregs(pid,&regs);
	printf("[++++] third pc:%x\n",regs.ARM_pc);
	printf("[++++] third lr:%x\n",regs.ARM_lr);
	printf("[++++] third cpsr:%x\n\n",regs.ARM_cpsr);
	return 0;
}

int ptrace_detach( pid_t pid )
{
	if ( ptrace( PTRACE_DETACH, pid, NULL, 0 ) < 0 )
	{
		perror( "ptrace_detach" );
		return -1;
	}

	return 0;
}