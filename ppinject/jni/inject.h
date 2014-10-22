#pragma once

#include <sys/types.h>


int inject_remote_process( int target_pid, const char *library_path, const char *function_name, void *param, size_t param_size );

int find_pid_of( const char *process_name );

void* get_module_base( int pid, const char* module_name );

struct inject_param_t
{
	int from_pid;
} ;
