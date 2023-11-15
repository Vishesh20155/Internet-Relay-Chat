CC = gcc
CFLAGS = -pthread -lcrypto -lssl
CLIENT_TARGET = client
SERVER_TARGET = server

all: $(CLIENT_TARGET) $(SERVER_TARGET)

$(CLIENT_TARGET): Client/client.c
	$(CC) $< -o $@ $(CFLAGS)

$(SERVER_TARGET): Server/server.c
	$(CC) $< -o $@ $(CFLAGS)

clean:
	rm -f $(CLIENT_TARGET) $(SERVER_TARGET)

.PHONY: all clean