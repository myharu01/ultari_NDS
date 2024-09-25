CC = gcc

CFLAGS = -Wall -g -O0 -I$(INCLUDE) -DMG_TLS=MG_TLS_OPENSSL
LDFLAGS = -lcurl -lxml2 -lpthread $(shell xml2-config --cflags) -ljwt -lnftables -lssl -lcrypto

OBJS = main.o mongoose.o authserver.o net.o get_info.o client_list.o copy.o firewall.o input_validation.o

OBJSAUTH = auth_sh.o input_validation.o

INCLUDE = include/

all: ultari auth_sh

ultari: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

auth_sh : $(OBJSAUTH)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o ultari auth_sh

.PHONY: clean all
