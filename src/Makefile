CC = gcc

mad: mad.o cli.o cmds.o madELF.o pool.o util.o
	gcc -fPIE -Wl,-z,relro,-z,now -Wall -Wextra $^ -o ../mad

mad.o: mad.c
	gcc -c -fstack-protector-all -Wall -Wextra mad.c -o mad.o

cmd.o: cmds.c cmds.h
	gcc -c -fstack-protector-all -Wall -Wextra cmds.c -o cmds.o

cli.o: cli.c cli.h
	gcc -c -fstack-protector-all -Wall -Wextra cli.c -o cli.o

madELF.o: madELF.c madELF.h
	gcc -c -fstack-protector-all -Wall -Wextra madELF.c -o madELF.o

pool.o: pool.c pool.h
	gcc -c -fstack-protector-all -Wall -Wextra pool.c -o pool.o

util.o: util.c util.h
	gcc -c -fstack-protector-all -Wall -Wextra util.c -o util.o

clean:
	rm *.o