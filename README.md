# pam_researchit
A simple PAM module to do misc tasks on login.
Right now all this does is associate usernames with
accounts in Slurm's accounting system based on a group
naming scheme. The account must already exist in Slurm's
accounting DB and must have the same name as the group you're 
targeting in AD.

ie if the user is in snehring-lab (the default filter is -lab) this
module will enumerate the list of groups that the user is in, find
that they are in snehring-lab and attempt to add that user to the
snehring-lab that is in Slurm's account Database. If the user already
exists in Slurm, it exits.

## Module Usage
This should be placed in the session section of the PAM config. You'll
likely want it to be optional, but it shouldn't matter.

### Arguments
Currently the only arguments defined are group_regex which is the POSIX regex
to be used to filter groups down to the desired groups. If you specify a
compound regex ie ```foo|bar``` the first regex is assumed to be the one you want your default slurm account to be for each user.

Default is:
```
group_regex=^[[:alnum:]]*-lab$
```
and parent_account which is the account (that must exist) in the slurm accounting database
that all accounts created by this should be descended from.
Default is:
```
parent_account=pronto
```