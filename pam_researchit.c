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
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <wait.h>
#include <fcntl.h>

#define MODULE_NAME "pam_researchit"
#define MAX_GROUPS 128
// group name length limit on rhel
#define GROUP_NAME_LIMIT 32
#define USER_NAME_LIMIT 32
// why is your regex longer than 255
#define MAX_REGEX_LENGTH 255
#define DEFAULT_GROUP_REGEX "^[[:alnum:]]*-lab$"
#define DEFAULT_ZFS_ROOT "tank/home"

char** get_string_array(int32_t nstrings, int32_t length);
char** get_group_array(int32_t ngroups);
void free_string_array(char** array, int32_t size);
int32_t get_groups(const char* username, char** buf);
int32_t filter_groups(char*** buf, int32_t size, const char* regex);
int32_t create_home_dataset(const char* name, const char* parent);
int32_t run_command(const char* cmd, char** argv, void* output);
int32_t slurm_check_user(const char* name);
int32_t slurm_add_user(const char* username, int32_t naccounts, const char** accounts);

PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	//TODO
	int32_t retval;
	int32_t error = PAM_SUCCESS;
	const char** temp;
	char* username;
	char* zfs_root;
	char* group_regex;
	char* token;
	int32_t ngroups = MAX_GROUPS;
	char** groups = get_group_array(MAX_GROUPS);
	if(groups == (char**)-1)
	{
		pam_syslog(pamh, LOG_CRIT, "Failed to allocate memory.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;
	}
	username = calloc(USER_NAME_LIMIT+1, sizeof(char));
	group_regex = calloc(MAX_REGEX_LENGTH+1, sizeof(char));
	zfs_root = calloc(ZFS_MAX_DATASET_NAME_LEN+1, sizeof(char));
	token = calloc(256, sizeof(char));
	if(username == (char*)NULL || group_regex == (char*)NULL || zfs_root == (char*)NULL || token == (char*)NULL)
	{
		pam_syslog(pamh, LOG_CRIT, "Failed to allocate memory.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;
	}
	// argument parsing
	zfs_root = DEFAULT_ZFS_ROOT;
	group_regex = DEFAULT_GROUP_REGEX;
	for(int i = 0; i < argc; i++)
	{
		strncpy(token, argv[i], 256);
		char* key = strtok(token,"=");
		char* value = strtok(NULL,"=");
		if(strcmp(key, "zfs_root") == 0)
		{
			strncpy(zfs_root, value, ZFS_MAX_DATASET_NAME_LEN+1);
		}
		if(strcmp(key, "group_regex")== 0)
		{
			strncpy(group_regex, value, MAX_REGEX_LENGTH+1);
		}
	}

	//get username
	retval = pam_get_user(pamh, temp, "\0");
	if(retval != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get username.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;

	}
	strcpy(username,*temp);
	if(username=="root")
	{
		//stop and exit
	}
	// get and then filter groups
	retval = get_groups(username,groups);
	if(retval == -1)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get group list for user %s", username);
		error = PAM_SESSION_ERR;
		goto cleanup;
	}
	retval = filter_groups(&groups,retval,group_regex);
	if(retval == -1)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to filter groups for whatever reason for user %s.", username);
		error = PAM_SESSION_ERR;
		goto cleanup;
	}
	
	
	// ZFS STUFF
	retval = create_home_dataset(username,zfs_root);
	//honestly it's not super important if the dataset creation fails.
	if(retval)
	{
		if(retval==ENAMETOOLONG)
		{
			pam_syslog(pamh, LOG_INFO, "Dataset creation for %s failed due to having too long a name.", username);
		} else {
			pam_syslog(pamh, LOG_INFO, "Dataset creation for %s failed for some reason.", username);
		}
	}
	// determine group membership
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
	// 		add user account with defaultaccount of lab group, if fail complain
	// 	if more than one lab group
	// 		pick a default, add associations for all others, if fail complain.
cleanup:
	free(username);
	free(zfs_root);
	free(group_regex);
	free(groups);
	free(token);
	return error;
}
/**
 * returns pointer to an array of strings of the given dimensions
 */
char** get_string_array(int32_t nstrings, int32_t length)
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
char** get_group_array(int32_t ngroups)
{
	return get_string_array(ngroups,GROUP_NAME_LIMIT+1);
}
/**
 * free an array of strings of given size.
 */
void free_string_array(char** array, int32_t size)
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
int32_t get_groups(const char* username, char** buf)
{
	gid_t* groups; /** array of gid_t (gids basically) */
	int32_t ngroups = MAX_GROUPS; /** number of groups returned by getgrouplist */
	int32_t retval;
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
int32_t filter_groups(char*** buf, int32_t size, const char* regex_string)
{
	regex_t regex;
	char** temp = get_group_array(size);
	if(temp==(char**)-1)
	{
		// error
		return -1;
	}
    char** temper;
	int ret = regcomp(&regex, regex_string, REG_ICASE|REG_NOSUB|REG_EXTENDED);
	if(ret)
	{
		// regex compilation error
		return -1;
	}
	int32_t j = 0;
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
/**
 * Creates a ZFS dataset with the name parent/name
 * the parent is required to exist.
 * param name name of the dataset.
 * param parent parent dataset this will be a child of.
 */
int32_t create_home_dataset(const char* name, const char* parent)
{
	// TODO
	// testing
	int32_t error = 0;
	if(strnlen(parent,ZFS_MAX_DATASET_NAME_LEN)+strnlen(name,ZFS_MAX_DATASET_NAME_LEN)+1 > ZFS_MAX_DATASET_NAME_LEN)
	{
		// name would be too long.
		return ENAMETOOLONG;
	}
	// init
	error = libzfs_core_init();
	if(error)
	{
		// failed to init libzfs_core
		goto cleanup;
	}
	// allocate space for dataset name string
	char* dataset = calloc(ZFS_MAX_DATASET_NAME_LEN+1, sizeof(char));
	//assemble the string
	strncpy(dataset, parent, ZFS_MAX_DATASET_NAME_LEN);
	strncat(dataset,"/",2);
	strncat(dataset,name,ZFS_MAX_DATASET_NAME_LEN);
	if(lzc_exists(dataset))
	{
		// dataset already exists
		// this isn't an error dingus
		// this is like the most common mode of operation
		error = 0;
		goto cleanup;
	}
	// create the dataset as a regular zfs filesystem
	error = lzc_create(dataset,LZC_DATSET_TYPE_ZFS,NULL);
	if(error)
	{
		goto cleanup;
	}
cleanup:
	libzfs_core_fini();
	return error;
}

/**
 * Executes the command specified by cmd and returns its exit code.
 * param cmd command to execute
 * param argv arguments to command (the first must be the command being executed)
 * param output optional buffer where the contents of stdout should go (single line 255 characters max).
 */
int32_t run_command(const char* cmd, char** argv, void* output)
{
	int32_t out_pipe[2];
	int32_t child_pid;
	int32_t status = 0;
	int32_t ret= 0;
	FILE* out_file;
	int32_t blackhole;

	blackhole = open("/dev/null", O_WRONLY);
	if(output == NULL)
	{
		out_pipe[0] = open("/dev/null", O_WRONLY);
		out_pipe[1] = open("/dev/null", O_WRONLY);
	}
	else
	{
		pipe(out_pipe);
	}
	
	child_pid = fork();

	if(child_pid>0)
	{
		//parent
		close(out_pipe[1]);
		out_file = fdopen(out_pipe[0], "r");
		fgets(output, 255, out_file);
		close(out_pipe[0]);
		waitpid(child_pid,&status,0);
		close(blackhole);
		// check exit status
		if(!WIFEXITED(status))
		{
			return -1;
		}
		return WEXITSTATUS(status);

	}
	else if(child_pid==0)
	{
		//child
		close(out_pipe[0]);
		// output redirection
		dup2(out_pipe[1], STDOUT_FILENO);
		dup2(blackhole, STDERR_FILENO);
		execvp(cmd, argv);
		exit(errno);

	} 
	else 
	{
		return -1;
	}

}
int32_t slurm_check_user(const char* name)
{
	// TOOD
}

int32_t slurm_add_user(const char* username, int32_t naccounts, const char** accounts)
{
	// TODO
}