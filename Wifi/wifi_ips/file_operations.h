/*
 * file_operations.h
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#include "main.h"

#define SIZEOF_MAC_IP 10
#define NO_OF_BYTES_IP 4
#define NO_OF_BYTES_MAC 6

extern int init_access_ctrl_list(FILE *fp, unsigned char **acl_list);
void init_output_csv(char *file1, char *file2);
