#pragma once

#include <sys/types.h>

#ifdef __cplusplus
extern "C"
{
#endif

int inject_remote_process( pid_t target_pid, const char *library_path, const char *function_name, void *param, size_t param_size );

int find_pid_of( const char *process_name );

void* get_module_base( pid_t pid, const char* module_name );

#ifdef __cplusplus
}
#endif


struct inject_param_t
{
	pid_t from_pid;
} ;
