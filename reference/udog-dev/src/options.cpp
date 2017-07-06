#include "options.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
//#define _GNU_SOURCE		/* 为了支持getopt_long */
#include <getopt.h>

void usage() {
	printf("udog [options] file\n");
	printf("http://www.nagapt.com\n");
	show_version();
}

void show_version() {
	printf("V%s\n", UDOG_VERSION_STRING);
}

void show_help() {
	printf("\t----------------------------------------\n");
	printf("\t|==== Android Native Lib Cracker ====  |\n");
	printf("\t----------------------------------------\n");
	printf("udog [options] file\n");
	printf("-d, --dump=file                     dump load so to file\n");
	printf("--clear-entry                       clear DT_INIT value\n");
	printf("-c, --check                         print code sign\n");
	printf("--xcto=offset(hex)                  set xct offset\n");
	printf("--xcts=size(hex)                    set xct size\n");
	printf("-h, --help                          show help\n");
	printf("-v, --version                       show version\n");
	printf("--debug=level                       show debug information\n");
	printf("http://www.nagapt.com\n");
	show_version();
	printf("\n");
}

struct options_t* handle_arguments(int argc, char* argv[]) {
	static struct options_t opts;
	memset(&opts, 0, sizeof(opts));
	opts.call_dt_init = true;
	opts.call_dt_init_array = true;
	opts.call_dt_finit = true;
	opts.call_dt_finit_array = true;
	opts.load_pre_libs = true;
	opts.load_needed_libs = true;

	int opt;
	int longidx;
	int dump = 0, help = 0, version = 0,
		debug = 0, check = 0, xcto = 0,
		xcts = 0, clear_entry = 0;

	if (argc == 1) {
		return NULL;
	}

	const char* short_opts = ":hvcd:";
	struct option long_opts[] = {
	 	{ "dump", 1, &dump, 1 },
		{ "help", 0, &help, 2 },
		{ "version", 0, &version, 3 },
		{ "debug", 1, &debug, 4 },
		{ "check", 0, &check, 5 },
		{ "xcto", 1, &xcto, 6 },
		{ "xcts", 1, &xcts, 7 },
		{ "clear-entry",0, &clear_entry, 8 },
	 	{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, short_opts, long_opts, &longidx)) != -1) {
		switch (opt) {
		case 0:
			if (dump == 1) {
				opts.dump = true;
				opts.not_relocal = false;
				opts.make_sectabs = true;
				strcpy(opts.dump_file, optarg);
				opts.load = true;
				dump = 0;
			} else if (help == 2) {
				opts.help = true;
				help = 0;
			} else if (version == 3) {
				opts.version = true;
				version = 0;
			} else if (debug == 4) {
				opts.debug = true;
				opts.debuglevel = atoi(optarg);
				debug = 0;
			} else if (check == 5) {
				opts.check = true;
				check = 0;
			} else if (xcto == 6) {
				opts.xct_offset = strtol(optarg, NULL, 16);
				xcto = 0;
			} else if (xcts == 7) {
				opts.xct_size = strtol(optarg, NULL, 16);
				xcts = 0;
			} else if (clear_entry == 8) {
				opts.clear_entry = true;
				clear_entry = 0;
			} else {
				//printf("unknow options: %c\n", optopt);
				return NULL;
			}
			break;
		case 'c':
			opts.check = true;
			break;
		case 'h':
			opts.help = true;
			break;
		case 'v':
			opts.version = true;
			break;
		case 'd':
			opts.dump = true;
			opts.not_relocal = false;
			opts.make_sectabs = true;
			strcpy(opts.dump_file, optarg);
			opts.load = true;
			break;
		case '?':
			//printf("unknow options: %c\n", optopt);
			return NULL;
			break;
		case ':':
			//printf("option need a option\n");
			return NULL;
			break;
		}/* end switch */
	}/* end while */

	/* 无文件 */
	if (optind == argc) {
		return NULL;
	}

	strcpy(opts.target_file, argv[optind]);

	return &opts;
}



