CC = gcc

CFLAGS = -Wall -g -O0 -I$(INCLUDE) -DMG_TLS=MG_TLS_OPENSSL
LDFLAGS = -lcurl

OBJS = auth_curl.o input_validation.o

INCLUDE = include/

all: auth_curl

%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)

auth_curl: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o ultari auth_curl

.PHONY: clean all
