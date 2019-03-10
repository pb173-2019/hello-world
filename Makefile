default: all

all: api build

api:
	doxygen Doxyfile

build:
	mkdir build
	cd build && cmake .. && make

.PHONY: clean
clean:
	rm -rf api build
