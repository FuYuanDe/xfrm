include ../Config
ifeq ($(HAVE_MNL),y)

TIPCOBJ=bearer.o \
    cmdl.o link.o \
    media.o misc.o \
    msg.o nametable.o \
    node.o socket.o \
    peer.o tipc.o

include ../Config

TARGETS=tipc
CFLAGS += $(shell $(PKG_CONFIG) libmnl --cflags)
LDLIBS += $(shell $(PKG_CONFIG) libmnl --libs)

endif

all: $(TARGETS) $(LIBS)

tipc: $(TIPCOBJ)
	$(QUIET_LINK)$(CC) $^ $(LDFLAGS) $(LDLIBS) -o $@

install: all
	install -m 0755 $(TARGETS) $(DESTDIR)$(SBINDIR)

clean:
	rm -f $(TIPCOBJ) $(TARGETS)
