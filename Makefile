
CC = gcc
CFLAGS = -Wall -Wextra -g -I./include -L/usr/local/lib -lpcap -lbsd

TARGET = program_name

SRC = src/ethernet_frame_parser.c \
      src/ip_packet_parser.c \
      src/network_if_finder.c \
      src/main.c

OBJ = $(SRC:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS)

%.o: %.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f $(OBJ) $(TARGET)

distclean: clean
	rm -f *~

rebuild: distclean all

run: $(TARGET)
	./$(TARGET)

-include $(OBJ:.o=.d)

