CFLAGS = -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 -arch x86_64 -arch arm64 -mmacosx-version-min=14.0
all: pam_yogafp.so pamcheck

pam_yogafp.so: pam_yogafp.c
	$(CC) $(CFLAGS) -bundle -o $@ $< -lpam
	codesign --force -s - $@

pamcheck: pamcheck.c
	$(CC) $(CFLAGS) -o $@ $< -lpam
	codesign --force -s - $@

clean:
	rm -f pam_yogafp.so pamcheck
