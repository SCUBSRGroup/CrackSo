/*
 ============================================================================
 Name        : libinject.c
 Author      :  
 Version     :
 Copyright   : 
 Description : Android shared library inject helper
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include <asm/ptrace.h>
#include <asm/user.h>
#include <asm/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <utils/Log.h>



#define ENABLE_DEBUG 1

#define PTRACE_PEEKTEXT 1
#define PTRACE_POKETEXT 4
#define PTRACE_ATTACH	16
#define PTRACE_CONT 	7
#define PTRACE_DETACH   17
#define PTRACE_SYSCALL	24
#define CPSR_T_MASK		( 1u << 5 )

#define  MAX_PATH 0x100

#define REMOTE_ADDR( addr, local_base, remote_base ) ( (uint32_t)(addr) + (uint32_t)(remote_base) - (uint32_t)(local_base) )

const char *libc_path = "/system/lib/libc.so";
const char *linker_path = "/system/bin/linker";


#if ENABLE_DEBUG
	#define DEBUG_PRINT(format,args...) \
		LOGD(format, ##args)
#else
	#define DEBUG_PRINT(format,args...)
#endif


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


	waitpid( pid, NULL, WUNTRACED );

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
	if ( ptrace( PTRACE_ATTACH, pid, NULL, 0  ) < 0 )
	{
		perror( "ptrace_attach" );
		return -1;
	}

	waitpid( pid, NULL, WUNTRACED );

	//DEBUG_PRINT("attached\n");

	if ( ptrace( PTRACE_SYSCALL, pid, NULL, 0  ) < 0 )
	{
		perror( "ptrace_syscall" );
		return -1;
	}



	waitpid( pid, NULL, WUNTRACED );

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

void* get_module_base( pid_t pid, const char* module_name )
{
	FILE *fp;
	long addr = 0;
	char *pch;
	char filename[32];
	char line[1024];

	if ( pid < 0 )
	{
		/* self process */
		snprintf( filename, sizeof(filename), "/proc/self/maps", pid );
	}
	else
	{
		snprintf( filename, sizeof(filename), "/proc/%d/maps", pid );
	}

	fp = fopen( filename, "r" );

	if ( fp != NULL )
	{
		while ( fgets( line, sizeof(line), fp ) )
		{
			if ( strstr( line, module_name ) )
			{
				pch = strtok( line, "-" );
				addr = strtoul( pch, NULL, 16 );

				if ( addr == 0x8000 )
					addr = 0;

				break;
			}
		}

				fclose( fp ) ;
	}

	return (void *)addr;
}


void* get_remote_addr( pid_t target_pid, const char* module_name, void* local_addr )
{
	void* local_handle, *remote_handle;

	local_handle = get_module_base( -1, module_name );
	remote_handle = get_module_base( target_pid, module_name );

	DEBUG_PRINT( "[+] get_remote_addr: local[%x], remote[%x]\n", local_handle, remote_handle );

	return (void *)( (uint32_t)local_addr + (uint32_t)remote_handle - (uint32_t)local_handle );
}

int find_pid_of( const char *process_name )
{
	int id;
	pid_t pid = -1;
	DIR* dir;
	FILE *fp;
	char filename[32];
	char cmdline[256];

	struct dirent * entry;

	if ( process_name == NULL )
		return -1;

	dir = opendir( "/proc" );
	if ( dir == NULL )
		return -1;

	while( (entry = readdir( dir )) != NULL )
	{
		id = atoi( entry->d_name );
		if ( id != 0 )
		{
			sprintf( filename, "/proc/%d/cmdline", id );
			fp = fopen( filename, "r" );
			if ( fp )
			{
				fgets( cmdline, sizeof(cmdline), fp );
				fclose( fp );

				if ( strcmp( process_name, cmdline ) == 0 )
				{
					/* process found */
					pid = id;
					break;
				}
			}
		}
	}

	closedir( dir );

	return pid;
}



int inject_remote_process( pid_t target_pid, const char *library_path, const char *function_name, void *param, size_t param_size )
{
	int ret = -1;
	void *mmap_addr, *dlopen_addr, *dlsym_addr, *dlclose_addr;
	void *local_handle, *remote_handle, *dlhandle;
	uint8_t *map_base;
	uint8_t *dlopen_param1_ptr, *dlsym_param2_ptr, *saved_r0_pc_ptr, *inject_param_ptr, *remote_code_ptr, *local_code_ptr;

	struct pt_regs regs, original_regs;
	extern uint32_t _dlopen_addr_s, _dlopen_param1_s, _dlopen_param2_s, _dlsym_addr_s, \
			_dlsym_param2_s, _dlclose_addr_s, _inject_start_s, _inject_end_s, _inject_function_param_s, \
			_saved_cpsr_s, _saved_r0_pc_s;

	uint32_t code_length;


	long parameters[10];



	DEBUG_PRINT( "[+] Injecting process: %d\n", target_pid );

	if ( ptrace_attach( target_pid ) == -1 )
		return EXIT_SUCCESS;


	if ( ptrace_getregs( target_pid, &regs ) == -1 )
		goto exit;

	/* save original registers */
	memcpy( &original_regs, &regs, sizeof(regs) );

	mmap_addr = get_remote_addr( target_pid, "/system/lib/libc.so", (void *)mmap );

	DEBUG_PRINT( "[+] Remote mmap address: %x\n", mmap_addr );

	/* call mmap */
	parameters[0] = 0;	// addr
	parameters[1] = 0x4000; // size
	parameters[2] = PROT_READ | PROT_WRITE | PROT_EXEC;  // prot
	parameters[3] =  MAP_ANONYMOUS | MAP_PRIVATE; // flags
	parameters[4] = 0; //fd
	parameters[5] = 0; //offset

	DEBUG_PRINT( "[+] Calling mmap in target process.\n" );

	if ( ptrace_call( target_pid, (uint32_t)mmap_addr, parameters, 6, &regs ) == -1 )
		goto exit;



	if ( ptrace_getregs( target_pid, &regs ) == -1 )
		goto exit;


	DEBUG_PRINT( "[+] Target process returned from mmap, return value=%x, pc=%x \n", regs.ARM_r0, regs.ARM_pc );

	map_base = (uint8_t *)regs.ARM_r0;

	dlopen_addr = get_remote_addr( target_pid, linker_path, (void *)dlopen );
	dlsym_addr = get_remote_addr( target_pid, linker_path, (void *)dlsym );
	dlclose_addr = get_remote_addr( target_pid, linker_path, (void *)dlclose );

	DEBUG_PRINT( "[+] Get imports: dlopen: %x, dlsym: %x, dlclose: %x\n", dlopen_addr, dlsym_addr, dlclose_addr );


	remote_code_ptr = map_base + 0x3C00;
	local_code_ptr = (uint8_t *)&_inject_start_s;


	_dlopen_addr_s = (uint32_t)dlopen_addr;
	_dlsym_addr_s = (uint32_t)dlsym_addr;
	_dlclose_addr_s = (uint32_t)dlclose_addr;

	DEBUG_PRINT( "[+] Inject code start: %x, end: %x\n", local_code_ptr, &_inject_end_s );

	code_length = (uint32_t)&_inject_end_s - (uint32_t)&_inject_start_s;
	dlopen_param1_ptr = local_code_ptr + code_length + 0x20;
	dlsym_param2_ptr = dlopen_param1_ptr + MAX_PATH;
	saved_r0_pc_ptr = dlsym_param2_ptr + MAX_PATH;
	inject_param_ptr = saved_r0_pc_ptr + MAX_PATH;


	/* dlopen parameter 1: library name */
	strcpy( dlopen_param1_ptr, library_path );
	_dlopen_param1_s = REMOTE_ADDR( dlopen_param1_ptr, local_code_ptr, remote_code_ptr );
	DEBUG_PRINT( "[+] _dlopen_param1_s: %x\n", _dlopen_param1_s );

	/* dlsym parameter 2: function name */
	strcpy( dlsym_param2_ptr, function_name );
	_dlsym_param2_s = REMOTE_ADDR( dlsym_param2_ptr, local_code_ptr, remote_code_ptr );
	DEBUG_PRINT( "[+] _dlsym_param2_s: %x\n", _dlsym_param2_s );

	/* saved cpsr */
	_saved_cpsr_s = original_regs.ARM_cpsr;

	/* saved r0-pc */
	memcpy( saved_r0_pc_ptr, &(original_regs.ARM_r0), 16 * 4 ); // r0 ~ r15
	_saved_r0_pc_s = REMOTE_ADDR( saved_r0_pc_ptr, local_code_ptr, remote_code_ptr );
	DEBUG_PRINT( "[+] _saved_r0_pc_s: %x\n", _saved_r0_pc_s );

	/* Inject function parameter */
	memcpy( inject_param_ptr, param, param_size );
	_inject_function_param_s = REMOTE_ADDR( inject_param_ptr, local_code_ptr, remote_code_ptr );
	DEBUG_PRINT( "[+] _inject_function_param_s: %x\n", _inject_function_param_s );

	DEBUG_PRINT( "[+] Remote shellcode address: %x\n", remote_code_ptr );
	ptrace_writedata( target_pid, remote_code_ptr, local_code_ptr, 0x400 );

	memcpy( &regs, &original_regs, sizeof(regs) );
	regs.ARM_sp = (long)remote_code_ptr;
	regs.ARM_pc = (long)remote_code_ptr;
	ptrace_setregs( target_pid, &regs );
	ptrace_detach( target_pid );

	// inject succeeded
	ret = 0;

exit:
	return ret;
}
int main(int argc, char** argv) {
	pid_t target_pid;
	target_pid = find_pid_of("/system/bin/servicemanager");
	inject_remote_process( target_pid, "/dev/yuki/payload.so", "hook_entry", "I'm parameter!", strlen("I'm parameter!") );
}