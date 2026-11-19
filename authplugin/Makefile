ARCH = -arch x86_64 -arch arm64 -mmacosx-version-min=14.0
CFLAGS = -O2 -Wall -Wextra -Werror -fstack-protector-strong -D_FORTIFY_SOURCE=2 $(ARCH)
BUNDLE = YogaFPAuth.bundle

all: $(BUNDLE) authtest

$(BUNDLE): YogaFPAuth.m Info.plist
	rm -rf $(BUNDLE)
	mkdir -p $(BUNDLE)/Contents/MacOS
	cp Info.plist $(BUNDLE)/Contents/Info.plist
	$(CC) $(CFLAGS) -fobjc-arc -bundle -o $(BUNDLE)/Contents/MacOS/YogaFPAuth YogaFPAuth.m \
	    -framework Foundation -framework AppKit -framework Security -framework OpenDirectory -framework SystemConfiguration
	codesign --force -s - $(BUNDLE)

authtest: authtest.c
	$(CC) $(CFLAGS) -o $@ $< -framework Security
	codesign --force -s - $@

clean:
	rm -rf $(BUNDLE) authtest
