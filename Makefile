ifdef TARGET
TARGET_PREFIX = $(TARGET)-
endif

ifndef CROSS_COMPILE
CROSS_COMPILE = $(TARGET_PREFIX)
endif

ifdef LOG_COLLECTOR
	CFLAGS += -DLOG_COLLECTOR=$(LOG_COLLECTOR)
endif

ifdef DEBUG_LEVEL
	CFLAGS += -DDEBUG_LEVEL=$(DEBUG_LEVEL)
endif

ifndef KERNEL_DIR
	KERNEL_DIR=/usr/src/linux
endif 

#CROSS_COMPILE=armeb-linux-uclibc-
CC = $(CROSS_COMPILE)gcc
LD = $(CROSS_COMPILE)gcc
STRIP = $(CROSS_COMPILE)strip
export CC LD 

EXEC = conn_redirect
OBJS += recv_pkt.o
OBJS += send_pkt.o
OBJS += conn_redirect.o

LIBPATH = -L../../$(TARGET_PREFIX)lib -L../../../$(TARGET_PREFIX)lib
LDFLAGS += $(LIBPATH) -lcsman

INCPATH = -I./ -I../../include -I../../../include
CFLAGS += $(INCPATH) 

all: $(EXEC)
	$(STRIP) $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $(EXEC)

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(EXEC) *.o
