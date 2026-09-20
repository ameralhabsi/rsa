TARGET = rsa
LIBS = -lm -lgmp
CC = gcc
CFLAGS = -g -Wall -O2

.PHONY: default all clean

default: $(TARGET)
all: default 

OBJECTS = rsa.o 
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(CFLAGS) -Wall $(LIBS) -o $@
	
clean:
	rm -f *.o
	rm -f $(TARGET)
	rm a.out