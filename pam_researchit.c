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
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <wait.h>


#define MODULE_NAME "pam_researchit"
#define MAX_GROUPS 128
// group name length limit on rhel
#define GROUP_NAME_LIMIT 32
#define USER_NAME_LIMIT 32
// why is your regex longer than 255
#define MAX_REGEX_LENGTH 255
#define DEFAULT_GROUP_REGEX "^[[:alnum:]]*-lab$"
#define DEFAULT_PARENT_ACCOUNT "pronto"

char** get_string_array(int32_t nstrings, int32_t length);
char** get_group_array(int32_t ngroups);
void free_string_array(char** array, int32_t size);
int32_t get_groups(const char* username, char** buf);
int32_t filter_groups(char*** buf, int32_t size, const char* regex);
int32_t run_command(const char* cmd, char** argv, void* output, int32_t size);
int32_t slurm_check_user(const char* name);
int32_t slurm_add_user(const char* username, int32_t naccounts, char** accounts);
int32_t slurm_check_account(const char* account);
int32_t slurm_add_account(const char* account, const char* parent);
pam_handle_t* pam_handle;

/**
 * arguments this module takes
 * group_regex posix regex to match for groups
 */
PAM_EXTERN int pam_sm_open_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	int32_t retval;
	int32_t error = PAM_SUCCESS;
	int32_t ngroups;
	const char* temp;
	char* username;
	char* group_regex;
	char* parent_account;
	char* token;
	char** groups = get_group_array(MAX_GROUPS);
	username = calloc(USER_NAME_LIMIT+1, sizeof(char));
	group_regex = calloc(MAX_REGEX_LENGTH+1, sizeof(char));
	parent_account = calloc(GROUP_NAME_LIMIT+1, sizeof(char));
	token = calloc(256, sizeof(char));
	pam_handle = pamh;
	
	if(groups == (char**)-1 || username == (char*)NULL || group_regex == (char*)NULL || token == (char*)NULL)
	{
		pam_syslog(pamh, LOG_CRIT, "Failed to allocate memory.");
		error = PAM_SYSTEM_ERR;
		goto cleanup;
	}
	// argument parsing
	strcpy(group_regex, DEFAULT_GROUP_REGEX);
	strcpy(parent_account, DEFAULT_PARENT_ACCOUNT);
	for(int i = 0; i < argc; i++)
	{
		strncpy(token, argv[i], 256);
		char* key = strtok(token,"=");
		char* value = strtok(NULL,"=");
		if(strcmp(key, "group_regex") == 0)
		{
			strncpy(group_regex, value, MAX_REGEX_LENGTH+1);
		}
		if(strcmp(key, "parent_account") == 0)
		{
			strncpy(parent_account, value, GROUP_NAME_LIMIT+1);
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
	
	// probably use slurmacctmgr
	// check if user account already exists, if so exit
	if(slurm_check_user(username))
	{
		// we're good here
		goto cleanup;
	}
	// user does not exist, let's go through the account list and make sure they all do before adding the user
	for(int32_t i = 0; i < ngroups; i++)
	{
		if(!slurm_check_account(groups[i]))
		{
			// account does not exist, add it
			if(slurm_add_account(groups[i], parent_account))
			{
				// error, continue, but be loud
				pam_syslog(pamh, LOG_INFO, "Failed to add accounts for user %s. This means they will not have an account in slurm. Fix it.", username);
				goto cleanup;
			}
		}

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
	free(group_regex);
	free(groups);
	free(token);
	return error;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t* pamh, int flags, int argc, const char** argv)
{
	pam_handle = NULL;
	return PAM_SUCCESS;
}
/**
 * returns pointer to an array of strings of the given dimensions
 * @param nstrings number of strings in the array
 * @param length length of the strings
 * @return a pointer to the array of strings specified which must be freed with free_string_array
 * @see free_string_array()
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
 * @param ngroups number of groups this array should hold
 * @return pointer to array of specified size
 */
char** get_group_array(int32_t ngroups)
{
	return get_string_array(ngroups,GROUP_NAME_LIMIT+1);
}
/**
 * free an array of strings of given size.
 * @param pointer to array created with get_string_array()
 * @param size of array
 * @see get_string_array()
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
 * @param username the username to look up groups for
 * @param buf an array of strings representing the group names
 * @return number of groups
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
		errno = 0;
		usergrp = getgrgid(groups[i]);
		int32_t error = errno;
		if(usergrp == NULL)
		{
			//if group lookup fails, which it can for _reasons_
			strncpy(buf[i], "fake-placeholder", 17);
			pam_syslog(pam_handle, LOG_INFO, "Lookup of gid %d for user %s failed. Error was: %s", groups[i], username, strerror(error));
			continue;
		}
		strncpy(buf[i], usergrp->gr_name,GROUP_NAME_LIMIT+1);
	}
	free(groups);
	return ngroups;
}

/**
 * Returns the number of groups that match the specified filter
 * this will also be the size of buf upon returning. Ensures that
 * first group will be one that matches the first regex assuming
 * the user is in one.
 * Returns -1 if error.
 * @param buf pointer to the string array that will be filtered
 * @param size size of the array of strings
 * @return number of groups that matched
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
	regfree(&regex);
	// sort
	char* tempex = calloc(MAX_REGEX_LENGTH, sizeof(char));
	strncpy(tempex, regex_string, MAX_REGEX_LENGTH);
	char* first_regex = strtok(tempex, "|");
	char* delim = strchr(tempex, '|');
	if(j > 1 && delim != NULL && first_regex != NULL)
	{
		// we need to sort because we have a compound regex
		ret = regcomp(&regex, first_regex, REG_ICASE|REG_NOSUB|REG_EXTENDED);
		if(ret)
		{
			// regex compilation error
			// not fatal
			goto cleanup;
		}
		// we know at this point that temper is a filtered array of groups
		char* holder;
		if(regexec(&regex, temper[0], 0, NULL, 0))
		{
			// first group does not match regex
			for(int i = 1; i < j; i++)
			{
				if(!regexec(&regex, temper[i], 0, NULL, 0))
				{
					// match, swap
					holder = temper[i-1];
					temper[i-1] = temper[i];
					temper[i] = holder;
					break;
				}
			}
		}
	}
cleanup:
	regfree(&regex);
	free(tempex);
    free_string_array(temp,size);
	free_string_array(*buf,size);
	*buf = temper;
	return j;

}

/**
 * Executes the command specified by cmd and returns its exit code.
 * @param cmd command to execute
 * @param argv arguments to command (the first must be the command being executed)
 * @param output optional buffer where the contents of stdout should go.
 * @param size the size of the optional buffer, must be set
 */
int32_t run_command(const char* cmd, char** argv, void* output, int32_t size)
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
			fgets(output, size, out_file);
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
 * @param user the user's username
 * @return 1 if the user exists, 0 if not, -1 if error.
 */
int32_t slurm_check_user(const char* name)
{
	int32_t buff_size = 32;
	char** args = get_string_array(9,USER_NAME_LIMIT+1);
	char* output = calloc(buff_size, sizeof(char));
	int32_t ret = 0;
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--readonly");
	strcpy(args[3], "--noheader");
	strcpy(args[4], "-P");
	strcpy(args[5], "list");
	strcpy(args[6], "user");
	strncpy(args[7], name, 33);
	free(args[8]);
	args[8] = (char*) NULL; //required for execvp call

	ret = run_command("sacctmgr",args,output,buff_size);
	if(ret == -1)
	{
		// an abnornal error occured
		goto cleanup;
	}
	if(strnlen(output,buff_size))
	{
		//if we get any output at all the user exists
		ret = 1;
	}
	else
	{
		ret = 0;
	}
cleanup:
	free_string_array(args,9);
	free(output);
	return ret;

}
/**
 * Associates the user with the given accounts in the slurm database
 * @param username username of user
 * @param naccounts the number of accounts the user is in
 * @param accounts array of strings containing the account names
 * @return 0 if successful 
 */
int32_t slurm_add_user(const char* username, int32_t naccounts, char** accounts)
{
	int32_t ret = 0;
	char** args = get_string_array(10, 33);
	if(args == (char**)-1)
	{
		ret = -1;
		goto cleanup;
	}
	free(args[7]);
	free(args[8]);
	// 32 33 length strings + 31 commas
	args[7] = calloc((32*(GROUP_NAME_LIMIT+1))+31, sizeof(char));
	//Space for group name and default account string
	args[8] = calloc(47, sizeof(char));
	if(args[7] == (char*)NULL || args[8] == (char*)NULL)
	{
		ret = -1;
		goto cleanup;
	}
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--noheader");
	strcpy(args[3], "--immediate");
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
	strcpy(args[7], "Accounts=");
	strncat(args[7], accounts[0], GROUP_NAME_LIMIT);
	for(int i = 1; i < naccounts; i++)
	{
		strcat(args[7],",");
		strncat(args[7],accounts[i], GROUP_NAME_LIMIT);
	}
	strcpy(args[8], "DefaultAccount=");
	strncat(args[8], accounts[0], GROUP_NAME_LIMIT);
	free(args[9]);
	args[9] = (char*) NULL; //required for execvp
	ret = run_command("sacctmgr", args, NULL, 0);
	if(ret != 0)
	{
		//presumably what's gone wrong here is the default account
	}
cleanup:
	free_string_array(args, 10);
	return ret;
}

/**
 * Check if an account exists in slurm
 * @param acccount account to check for existance
 * @return 1 if exists, 0 if not, -1 if error
 */
int32_t slurm_check_account(const char* account)
{
	int32_t ret = 0;
	int32_t buff_size = 32;
	char** args = get_string_array(9,GROUP_NAME_LIMIT+1);
	char* output = calloc(buff_size, sizeof(char));
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--readonly");
	strcpy(args[3], "--noheader");
	strcpy(args[4], "-P");
	strcpy(args[5], "list");
	strcpy(args[6], "account");
	strncpy(args[7], account, 33);
	free(args[8]);
	args[8] = (char*) NULL; //required for execvp call

	ret = run_command("sacctmgr",args,output,buff_size);
	if(args == (char**)-1)
	{
		// an abnornal error occured
		goto cleanup;
	}
	if(strnlen(output,buff_size))
	{
		//if we get any output at all the user exists
		ret = 1;
	}
	else
	{
		ret = 0;
	}
cleanup:
	free_string_array(args,9);
	free(output);
	return ret;
}

/**
 * Add an account to slurm
 * @param account to add to slurm
 * @param parent_account account which this account should descend from
 * @return 0 on success
 */
 int32_t slurm_add_account(const char* account, const char* parent)
 {
	int32_t ret = 0;
	char** args = get_string_array(11, 33);
	if(args == (char**)-1)
	{
		ret = -1;
		goto cleanup;
	}
	//allocate longer strings for these
	free(args[7]);
	free(args[8]);
	free(args[9]);
	args[7] = calloc(23+GROUP_NAME_LIMIT, sizeof(char));
	args[8] = calloc(13+GROUP_NAME_LIMIT, sizeof(char));
	args[9] = calloc(7+GROUP_NAME_LIMIT, sizeof(char));
	if(args[7] == (char*)NULL || args[8] == (char*)NULL || args[9] == (char*)NULL)
	{
		ret = -1;
		goto cleanup;
	}
	//assemble the arguments
	strcpy(args[0], "sacctmgr");
	strcpy(args[1], "--quiet");
	strcpy(args[2], "--noheader");
	strcpy(args[3], "--immediate");
	strcpy(args[4], "add");
	strcpy(args[5], "account");
	strncpy(args[6], account, GROUP_NAME_LIMIT+1);
	strcat(args[7], "Description=");
	strncat(args[7], account, GROUP_NAME_LIMIT);
	strcat(args[7], "'s account");
	strcat(args[8], "Organization=");
	strncat(args[8], account, GROUP_NAME_LIMIT);
	strcpy(args[9], "Parent=");
	strncat(args[9], parent, GROUP_NAME_LIMIT);
	free(args[10]);
	args[10] = (char*) NULL; //required for execvp
	ret = run_command("sacctmgr", args, NULL, 0);

cleanup:
	free_string_array(args, 11);
	return ret;
 }
