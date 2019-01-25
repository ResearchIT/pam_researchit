// Required for session management stuff
// which this reasonably falls under
#define PAM_SM_SESSION
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <grp.h>
#include <pwd.h>
#include <regex.h>
#include <errno.h>
#include <sys/types.h>
#define __USE_LARGEFILE64 //required for libspl's sys/stat.h
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <wait.h>
#include <libzfs_core.h>


#define MODULE_NAME "pam_researchit"
#define MAX_GROUPS 128
// group name length limit on rhel
#define GROUP_NAME_LIMIT 32
#define USER_NAME_LIMIT 32
// why is your regex longer than 255
#define MAX_REGEX_LENGTH 255
#define DEFAULT_GROUP_REGEX "^[[:alnum:]]*-lab$"
#define DEFAULT_ZFS_ROOT "tank/home"
#define DEFAULT_HOME_ROOT "/home"

char** get_string_array(int32_t nstrings, int32_t length);
char** get_group_array(int32_t ngroups);
void free_string_array(char** array, int32_t size);
int32_t get_groups(const char* username, char** buf);
int32_t filter_groups(char*** buf, int32_t size, const char* regex);
int32_t create_home_dataset(const char* name, const char* parent);
int32_t create_home_directory(const char* username, const char* path);
int32_t run_command(const char* cmd, char** argv, void* output);
int32_t slurm_check_user(const char* name);
int32_t slurm_add_user(const char* username, int32_t naccounts, char** accounts);

/**
 * arguments this module takes
 * zfs_root parent dataset that the home dataset for a user should be created in
 * home_root parent directory that home diretories are in
 * group_regex posix regex to match for groups
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	//TODO
	int32_t retval;
	int32_t error = PAM_SUCCESS;
	int32_t ngroups;
	const char* temp;
	char* username;
	char* zfs_root;
	char* group_regex;
	char* home_root;
	char* token;
	char** groups = get_group_array(MAX_GROUPS);
	username = calloc(USER_NAME_LIMIT+1, sizeof(char));
	group_regex = calloc(MAX_REGEX_LENGTH+1, sizeof(char));
	zfs_root = calloc(ZFS_MAX_DATASET_NAME_LEN+1, sizeof(char));
	home_root = calloc(ZFS_MAX_DATASET_NAME_LEN+1, sizeof(char));
	token = calloc(256, sizeof(char));
	
	if(groups == (char**)-1 || username == (char*)NULL || group_regex == (char*)NULL || zfs_root == (char*)NULL || token == (char*)NULL)
	{
		pam_syslog(pamh, LOG_CRIT, "Failed to allocate memory.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;
	}
	// argument parsing
	strcpy(zfs_root, DEFAULT_ZFS_ROOT);
	strcpy(group_regex, DEFAULT_GROUP_REGEX);
	strcpy(home_root, DEFAULT_HOME_ROOT);
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
		if(strcmp(key, "home_root") == 0)
		{
			strncpy(home_root, value, 256);
		}
	}

	//get username
	retval = pam_get_user(pamh, &temp, NULL);
	if(retval != PAM_SUCCESS)
	{
		pam_syslog(pamh, LOG_INFO, "Failed to get username.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;

	}
	strcpy(username,temp);
	if(!strcmp(username,"root"))
	{
		error = PAM_SUCCESS;
		goto cleanup;
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
	ngroups = retval;
	
	// ZFS STUFF
	retval = create_home_dataset(username,zfs_root);
	//honestly it's not super important if the dataset creation fails.
	if(retval)
	{
		if(retval==ENAMETOOLONG)
		{
			pam_syslog(pamh, LOG_INFO, "Dataset creation for %s failed due to having too long a name.", username);
		} else {
			pam_syslog(pamh, LOG_WARNING, "Dataset creation for %s failed for some reason.", username);
		}
	}
	else
	{
		//skel stuff
		char* path = calloc(256, sizeof(char));
		if(path == (char*) NULL)
		{
			goto cleanup;
		}
		strncpy(path, home_root, 256);
		strncat(path, "/", 2);
		strncat(path, username, USER_NAME_LIMIT+1);
		retval = create_home_directory(username, path);
		free(path);
		if(retval)
		{
			// directory create failed, whine
			pam_syslog(pamh, LOG_WARNING, "Directory Creation for user %s failed for some reason.", username);
		}
	}
	
	// probably use slurmacctmgr
	// TODO
	// check if user account already exists, if so exit
	if(slurm_check_user(username))
	{
		// we're good here
		goto cleanup;
	}

	// attempt to add user to slurm account of all -lab groups
	// set DefaultAccount to first -lab group we see
	retval = slurm_add_user(username, ngroups, groups);
	if(retval)
	{
		// some sort of error occured, whine
		pam_syslog(pamh, LOG_WARNING, "An error was encountered when attempting to add user %s to the slurm account system.", username);
		goto cleanup;
	}
	
cleanup:
	free(username);
	free(zfs_root);
	free(group_regex);
	free(home_root);
	free(groups);
	free(token);
	return error;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	return PAM_SUCCESS;
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
	// TODO mount dataset with mount(2)
	
cleanup:
	libzfs_core_fini();
	return error;
}
/**
 * Does the whole 'mkhomedir' thing
 * Copies /etc/skel, which is more or less assumed to exist
 * Chowns (with the chown binary, because I'm lazy)
 * param username user who is to own this directory
 * param path path to the user's homedir (assumed to exist)
 */
int32_t create_home_directory(const char* username, const char* path)
{
	// assume path exists
	// copy skel
	// recursively set owner.
	// I could do all this in native C
	// or! I could use programs that already do this via my
	// crap execvp function.
	int32_t ret;
	struct stat status;
	char** args = get_string_array(4, ZFS_MAX_DATASET_NAME_LEN+1);
	if(lstat(path,&status) || lstat("/etc/skel", &status))
	{
		return errno;
	}

	strcpy(args[0], "cp");
	strcpy(args[1], "-r");
	strcpy(args[2], "/etc/skel/.");
	strncpy(args[3], path, ZFS_MAX_DATASET_NAME_LEN+1);
	ret = run_command("cp", args, NULL);
	if(ret)
	{
		free(args);
		return -1;
	}
	strcpy(args[0], "chown");
	strcpy(args[1], "-R");
	strncpy(args[2], username, 33);
	strncpy(args[3], path, ZFS_MAX_DATASET_NAME_LEN+1);
	ret = run_command("chown", args, NULL);
	free(args);
	if(ret)
	{
		return -1;
	}
	return 0;
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
		if(output != NULL)
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
/**
 * Checks if a user already exists in the slurm accountdb
 * param user the user's username
 * returns 1 if the user exists
 * returns 0 if the user does not exist
 * returns -1 if error
 */
int32_t slurm_check_user(const char* name)
{
	char** args = get_string_array(8,USER_NAME_LIMIT+1);
	char* output = calloc(32, sizeof(char));
	int32_t ret = 0;
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--readonly");
	strcpy(args[3], "--noheader");
	strcpy(args[4], "-P");
	strcpy(args[5], "list");
	strcpy(args[6], "user");
	strncpy(args[7], name, 33);

	ret = run_command("sacctmgr",args,output);
	if(ret == -1)
	{
		// an abnornal error occured
		goto cleanup;
	}
	if(strnlen(output,32))
	{
		//if we get any output at all the user exists
		ret = 1;
	}
	else
	{
		ret = 0;
	}
cleanup:
	free_string_array(args,8);
	free(output);
	return ret;

}
/**
 * Associates the user with the given accounts in the slurm database
 * param username username of user
 * param naccounts the number of accounts the user is in
 * param accounts array of strings containing the account names
 * return 0 if successful 
 */
int32_t slurm_add_user(const char* username, int32_t naccounts, char** accounts)
{
	char** args = get_string_array(9, 33);
	free(args[7]);
	// 32 33 length strings + 31 commas
	args[7] = calloc(1055, sizeof(char));
	if(args[7] == (char*)NULL)
	{
		free_string_array(args,9);
		return -1;
	}
	const char* acc = "Accounts=";
	const char* defacc = "DefaultAccount=";
	int32_t ret = 0;
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--noheader");
	strcpy(args[3], "-P");
	strcpy(args[4], "add");
	strcpy(args[5], "user");
	strncpy(args[6], username, USER_NAME_LIMIT+1);
	// args[7] is the account list
	// args[8] is the default account
	
	// assemble account string
	// logically, the user must be in one group at a minimum to have even been
	// able to get this far into the pam process in our environment.
	// but let's just check to be safe
	if(naccounts < 1)
	{
		ret =  -1;
		goto cleanup;
	}
	strncpy(args[7], acc, 10);
	strncat(args[7], accounts[0], 33);
	for(int i = 1; i < naccounts; i++)
	{
		strncat(args[7],",",2);
		strncat(args[7],accounts[i],33);
	}
	strncpy(args[8], defacc, 16);
	strncat(args[8], accounts[0], 33);
	ret = run_command("sacctmgr", args, NULL);
cleanup:
	free_string_array(args, 9);
	return ret;
}