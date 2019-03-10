default: build

all: api build

api:
	doxygen Doxyfile

build:
	mkdir build
	cd build && cmake ../src && make

.PHONY: clean
clean:
	rm -rf api build
