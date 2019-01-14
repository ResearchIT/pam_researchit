#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>

#define MAX_GROUPS 128
//group name length limit on rhel
#define GROUP_NAME_LIMIT 32
#define FILTER_REGEX "^[[:alnum:]]*-lab$"


/**
 * returns pointer to an array of strings of the given dimensions
 */
char** get_string_array(uint32_t nstrings, uint32_t length)
{
	char** ret = calloc(nstrings, sizeof(char*));
	if(ret==NULL)
	{
		// allocation failed
		return (char**)-1;
	}
	for(int i = 0 ; i < nstrings; i++)
	{
		ret[i] = calloc(length, sizeof(char));
		if(ret[i] == NULL)
		{
			// allocation failed;
			return (char**)-1;
		}
	}
	return ret;
}
/**
 * returns empty aray for ngroups groups
 */
char** get_group_array(uint32_t ngroups)
{
	return get_string_array(ngroups,GROUP_NAME_LIMIT+1);
}
/**
 * free an array of strings of given size.
 */
void free_string_array(char** array, uint32_t size)
{
	for(int i = 0; i < size; i++)
	{
		free(array[i]);
	}
	free(array);
}
/**
 * Returns the number of groups the given username is in
 * param username the username to look up groups for
 * param buf an array of strings representing the group names
 */
uint32_t get_groups(const char* username, char** buf)
{
	gid_t* groups; /** array of gid_t (gids basically) */
	uint32_t ngroups = MAX_GROUPS; /** number of groups returned by getgrouplist */
	uint32_t retval;
	struct passwd* userpwd; /** struct for passwd info */
	struct group* usergrp; /** struct for group info*/

	groups = calloc(MAX_GROUPS, sizeof(gid_t));
	// get passwd information for user, we need their main gid.
	userpwd = getpwnam(username);
	// get gids of groups user is in
	retval = getgrouplist(username, userpwd->pw_gid, groups, &ngroups);
	if(retval == -1)
		return -1;
	for(int i = 0; i < ngroups; i++)
	{
		usergrp = getgrgid(groups[i]);
		strncpy(buf[i], usergrp->gr_name,GROUP_NAME_LIMIT+1);
	}
	free(groups);
	return ngroups;
}

/**
 * Returns the number of groups that match the specified filter
 * this will also be the size of buf upon returning. Returns -1
 * if error.
 * param buf pointer to the string array that will be filtered
 * param size size of the array of strings
 */
uint32_t filter_groups(char*** buf, uint32_t size)
{
	regex_t regex;
	char** temp = get_group_array(size);
	if(temp==(char**)-1)
	{
		// error
		return -1;
	}
    char** temper;
	int ret = regcomp(&regex, FILTER_REGEX, REG_ICASE|REG_NOSUB|REG_EXTENDED);
	if(ret)
	{
		// regex compilation error
		return -1;
	}
	uint32_t j = 0;
	for(int i = 0; i < size; i++)
	{
		if(!regexec(&regex,(*buf)[i],0,NULL,0))
		{
			// match
			strncpy(temp[j++],(*buf)[i],GROUP_NAME_LIMIT+1);
		}
	}
    temper = get_group_array(j);
	if(temper==(char**)-1)
	{
		// error
		return -1;
	}
    for(int i = 0; i < j; i++)
    {
        strncpy(temper[i], temp[i],GROUP_NAME_LIMIT+1);
    }
    free_string_array(temp,size);
	free_string_array(*buf,size);
	*buf = temper;
	return j;

}



int main(int argc, char** argv)
{
    const char* username = "snehring";
    int ngroups = 128;
    gid_t* groups = calloc(ngroups, sizeof(gid_t));
    struct passwd* userpw;
    struct group* usergrp;
    userpw = getpwnam(username);
    int retval = getgrouplist(username, userpw->pw_gid, groups, &ngroups);
    char** group_names;
    if(retval == -1)
    {
        fprintf(stderr, "This user is in too many damn groups.\n");
        return EXIT_FAILURE;
    }
    printf("retval: %d\n", retval);
    printf("got %d groups back.\n",ngroups);
    if(ngroups==0)
    {
        printf("No groups.\n");
        exit(EXIT_SUCCESS);
    }
    group_names = get_group_array(ngroups);
    for(int i = 0; i < ngroups; i++)
    {
        printf("got this: %d\n", groups[i]);
        usergrp = getgrgid(groups[i]);
        if(usergrp != NULL)
        {
            printf("Which coresponds to this groupname: %s\n", usergrp->gr_name);
            strncpy(group_names[i], usergrp->gr_name, GROUP_NAME_LIMIT+1);
        }
    }
    retval = filter_groups(&group_names,ngroups);
    printf("retval of filter is: %d.\n",retval);
    for(int i = 0; i < retval; i++)
    {
        printf("Got %s as a match.\n", group_names[i]);
    }
    free(groups);
    free_string_array(group_names,retval);
    return EXIT_SUCCESS;
}
