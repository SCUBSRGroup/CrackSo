#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#define UNUSED __attribute__((unused))
#define UDOG_VERSION_STRING "1.0"

struct options_t {
	bool call_dt_init;
	bool call_dt_init_array;
	bool call_dt_finit;
	bool call_dt_finit_array;
	bool load_pre_libs;
	bool load_needed_libs;

	bool load;
	bool not_relocal;              /* 不进行重定位 */
	bool make_sectabs;             /* 制作节表 */
	bool dump;
	bool help;
	bool version;
	bool debug;
	bool check;
	bool clear_entry;

	int debuglevel;
	unsigned xct_offset;
	unsigned xct_size;
	char dump_file[128];
	char target_file[128];
};

struct options_t* handle_arguments(int argc, char* argv[]);
void usage();
void show_help();
void show_version();

#endif
