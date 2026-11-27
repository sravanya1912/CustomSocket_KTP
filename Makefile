CC      = gcc
CFLAGS  = -Wall -Wextra -O2 -g -pthread -D_GNU_SOURCE
LDFLAGS = -pthread -lrt

LIB     = libksocket.a
LIB_OBJ = ksocket.o

.PHONY: all library init user1 user2 test clean package

all: library init user1 user2

library: $(LIB)

$(LIB): $(LIB_OBJ)
	ar rcs $@ $^

ksocket.o: ksocket.c ksocket.h
	$(CC) $(CFLAGS) -c ksocket.c -o ksocket.o

init: initksocket
initksocket: initksocket.c ksocket.h $(LIB)
	$(CC) $(CFLAGS) initksocket.c -L. -lksocket $(LDFLAGS) -o initksocket

user1: user1.c ksocket.h $(LIB)
	$(CC) $(CFLAGS) user1.c -L. -lksocket $(LDFLAGS) -o user1

user2: user2.c ksocket.h $(LIB)
	$(CC) $(CFLAGS) user2.c -L. -lksocket $(LDFLAGS) -o user2

test: all
	@echo "Run manual tests - see README.md"

clean:
	rm -f *.o $(LIB) initksocket user1 user2
	rm -f /tmp/ktp_ctrl.sock
	-rm -f /dev/shm/ktp_shared_mem 2>/dev/null || true

package: clean
	cd .. && tar czf ktp-project.tar.gz ktp-project \
		--exclude='ktp-project/*.o' \
		--exclude='ktp-project/initksocket' \
		--exclude='ktp-project/user1' \
		--exclude='ktp-project/user2' \
		--exclude='ktp-project/libksocket.a'
	@echo "Created ../ktp-project.tar.gz"
