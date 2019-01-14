// Required for session management stuff
// which this reasonably falls under
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <libzfs_core.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>


#define MODULE_NAME "pam_researchit"
#define MAX_GROUPS 128
//group name length limit on rhel
#define GROUP_NAME_LIMIT 32
#define FILTER_REGEX "^[[:alnum:]]*-lab$"

char** get_string_array(uint32_t nstrings, uint32_t length);
char** get_group_array(uint32_t ngroups);
void free_string_array(char** array, uint32_t size);
uint32_t get_groups(const char* username, char** buf);
uint32_t filter_groups(char*** buf, uint32_t size);

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	//TODO
	uint32_t retval;
	const void** item;
	const char* username;
	uint32_t ngroups = MAX_GROUPS;
	char** groups = get_string_array(MAX_GROUPS, GROUP_NAME_LIMIT+1);
	if(groups==-1)
	{
		pam_syslog(pamh, LOG_CRIT, "Failed to allocate memory.");
		return PAM_SYSTEM_ERR;
	}


	//get username
	retval = pam_get_item(pamh, PAM_USER, item);
	if(retval != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get username.");
		return PAM_SYSTEM_ERR;

	}
	strcpy(username,(const char *)item[0]);
	
	
	// ZFS STUFF //either use libzfs_core or fork() zfs
	// get root data set from parameter or hardcode
	// check if root/USERNAME exists
	// if not, create
	//
	// determine group membership
	// if possible, get group list of las-machinename-group
	// probably use slurmacctmgr
	// 	//TODO
	//	decide if make a pseudo library (unmaintainable)
	//	decide if use libslurm/libslurmdbd (sucks, but can steal alot from user_functions.c in sacctmgr, also maintainability concerns)
	//	fork and use slurmacctmgr directly (probably easier, but sort of shitty)
	// check if user account already exists, if so exit
	//
	// attempt to add user to slurm account of all -lab groups
	// set DefaultAccount to first -lab group we see
	// deal with fallout of attempt to add to accounts that don't exist
	//
	// requiring admins to add the lab accounts prior to things being expected to work is easier logically and will simplify the pseudo code below
	//
	// 	if one lab group
	// 		if we're going to allow this module to create accounts, then create lab account, add user with DefaultAccount
	// 		if not fail and whine about it
	// 	if more than one lab group
	// 		if we're allowed to add accounts
	// 			if we have membership list of las-machinename-group
	// 				if only one group is in list, add it
	// 				if multiple all in list pick one to be default (admin can change later)
	// 			if we don't have membership list
	// 				if only one, attempt to add, if fail, whine loudly
	// 				if multiple
	// 					try until successful, elminate bad groups, pick default at random, if fail whine loudly
	// 		if not allowed to add accounts
	// 			check, eliminate until successful and pick default, if fail whine loudly
}
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
