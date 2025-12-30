DEFS += \
	-DSYSCONFDIR=\"$(sysconfdir)\"

AM_CPPFLAGS = $(I3BLOCKS_CPPFLAGS)

bin_PROGRAMS = i3blocks
i3blocks_SOURCES = \
	src/bar.c \
	src/block.c \
	src/config.c \
	src/i3bar.c \
	src/ini.c \
	src/json.c \
	src/line.c \
	src/main.c \
	src/map.c \
	src/sys.c \
	inc/bar.h \
	inc/block.h \
	inc/config.h \
	inc/ini.h \
	inc/json.h \
	inc/line.h \
	inc/log.h \
	inc/map.h \
	inc/sys.h \
	inc/term.h

dist_man1_MANS = \
	docs/i3blocks.1

dist_sysconf_DATA = \
	data/i3blocks.conf

if ENABLE_BASH_COMPLETION
bashcompletiondir = $(BASH_COMPLETION_DIR)
bashcompletion_DATA = data/bash-completion

install-data-local: install-bashcompletionDATA
	( cd '$(DESTDIR)$(BASH_COMPLETION_DIR)' && mv bash-completion i3blocks )

uninstall-local:
	( cd '$(DESTDIR)$(BASH_COMPLETION_DIR)' && rm -rf i3blocks )
endif
