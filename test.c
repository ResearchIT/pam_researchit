#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <grp.h>
#include <pwd.h>

int main(int argc, char** argv)
{
    const char* username = "snehring";
    int ngroups = 128;
    gid_t* groups = calloc(ngroups, sizeof(gid_t));
    struct passwd* userpw;
    struct group* usergrp;
    userpw = getpwnam(username);
    int retval = getgrouplist(username, userpw->pw_gid, groups, &ngroups);
    if(retval == -1)
    {
        fprintf(stderr, "This user is in too many damn groups.\n");
        return EXIT_FAILURE;
    }
    printf("retval: %d\n", retval);
    printf("got %d groups back.\n",ngroups);
    for(int i = 0; i < ngroups; i++)
    {
        if(groups[i] < 1000)
        {
            printf("Skipping low numbered group.\n");
            continue;
        }
        printf("got this: %d\n", groups[i]);
        usergrp = getgrgid(groups[i]);
        if(usergrp != NULL)
        {
            printf("Which coresponds to this groupname: %s\n", usergrp->gr_name);
        }
    }

    free(groups);
    return EXIT_SUCCESS;
}