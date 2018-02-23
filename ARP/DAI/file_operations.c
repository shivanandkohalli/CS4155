/*
 * file_operations.c
 *
 *  Created on: 23-Feb-2018
 *      Author: shiva
 */

#include "file_operations.h"
#include <string.h>

// Construct the access control list
// Convert the ascii string read to integers and cache it
int init_access_ctrl_list(FILE *fp, unsigned char **acl_list)
{
	int acl_list_count = 0;
    char * line = NULL;
    size_t len = 0;
    ssize_t read;

    unsigned char *mac_ip;

    int i=0;
    int count =0;
    char temp_array[100];
    int temp_count=0;
    int j=0;
    unsigned char l=0;

    while ((read = getline(&line, &len, fp)) != -1) {
        mac_ip = (unsigned char *)malloc(SIZEOF_MAC_IP);
        //strcpy(acl_list[acl_list_count++], line);
        count = 0;
        for(i=0;i<NO_OF_BYTES_IP;i++)
        {
        	j=0;
        	while(!(line[count] == '.' || line[count] == ' '))
        	{
        		temp_array[j++] = line[count++];
        	}
        	temp_array[j] = '\0';
        	count++;
        	l=strtol(temp_array, NULL, 0);
        	mac_ip[i] = l;
        }

        temp_count = i;
        for(i=0;i<NO_OF_BYTES_MAC;i++)
        {
        	j=0;
        	while(!(line[count] == ':' || line[count] == ' '|| line[count] == '\n'))
        	{
        		temp_array[j++] = line[count++];
        	}
        	temp_array[j] = '\0';
        	count++;
        	mac_ip[i+temp_count] = strtol(temp_array, NULL, 16);
        }

        acl_list[acl_list_count++] = mac_ip;
    }
    return acl_list_count;
}


