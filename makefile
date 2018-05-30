# build an executable named myprog from myprog.c
  all: geemail.cpp 
# 	gcc -g -Wall -o myprog myprog.c
	g++ -std=c++11 sha256.cpp geemail.cpp -o geemail -lsqlite3 -lgcrypt -w 
  clean: 
	  $(RM) geemail
