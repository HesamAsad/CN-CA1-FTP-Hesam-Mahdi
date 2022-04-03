COMPILE_FLAGS = -std=c++11 -c

all: server

server: main.o server.o json.o User.o tools.o
	g++ main.o server.o json.o User.o tools.o $(FLAGS) -o server -lpthread

main.o: main.cpp server.h
	g++ $(COMPILE_FLAGS) main.cpp

server.o: server.cpp server.h ../Json/json.h tools.h
	g++ $(COMPILE_FLAGS) server.cpp

json.o: ../Json/json.cpp ../Json/json.h User.h
	g++ $(COMPILE_FLAGS) ../Json/json.cpp

User.o: User.cpp User.h
	g++ $(COMPILE_FLAGS) User.cpp

tools.o: tools.cpp tools.h
	g++ $(COMPILE_FLAGS) tools.cpp

.PHONY: clean

clean:
		rm *.o
		rm server
		rm log.txt