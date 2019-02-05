default: pam_researchit.so

pam_researchit.o: pam_researchit.c
	$(CC) -std=gnu11 -Wall -Werror -shared -fPIC -c pam_researchit.c -o pam_researchit.o
pam_researchit.so: pam_researchit.o
	$(CC) -std=gnu11 -Wall -Werror -shared -fPIC -lpam pam_researchit.o -o pam_researchit.so
clean:
	rm -f pam_researchit.o pam_researchit.so

