default: pam_researchit.so
OURCFLAGS=-std=gnu11 -O2 -Wall -Werror -shared -fPIC

pam_researchit.o: pam_researchit.c
	$(CC) $(OURCFLAGS) -c pam_researchit.c -o pam_researchit.o
pam_researchit.so: pam_researchit.o
	$(CC) $(OURCFLAGS) -lpam pam_researchit.o -o pam_researchit.so
clean:
	rm -f pam_researchit.o pam_researchit.so

