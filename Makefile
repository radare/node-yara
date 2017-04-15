
BASE=$(shell pwd)

FILE=5.30
YARA=3.5.0
ZLIB=1.2.11

libyara:

all: zlib file yara

zlib:
	-rm -rf $(BASE)/deps/zlib-$(ZLIB)
	cd $(BASE)/deps && tar -xzvf zlib-$(ZLIB).tar.gz
	cd $(BASE)/deps/zlib-$(ZLIB) && ./configure --prefix=$(BASE)/deps/zlib-$(ZLIB)/build
	cd $(BASE)/deps/zlib-$(ZLIB) && make
	cd $(BASE)/deps/zlib-$(ZLIB) && make install

file:
	-rm -rf $(BASE)/deps/file-$(FILE)
	cd $(BASE)/deps && tar -xzvf file-$(FILE).tar.gz
	cd $(BASE)/deps/file-$(FILE) && ./configure --prefix=$(BASE)/deps/file-$(FILE)/build --enable-shared --enable-static --enable-zlib --with-pic "CFLAGS=-I$(BASE)/deps/zlib-$(ZLIB)/build/include" "LDFLAGS=-L$(BASE)/deps/zlib-$(ZLIB)/build/lib"
	cd $(BASE)/deps/file-$(FILE) && make
	cd $(BASE)/deps/file-$(FILE) && make install

yara:
	-rm -rf $(BASE)/deps/yara-$(YARA)
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz
	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && ./configure --enable-static --disable-shared --with-pic --enable-magic --prefix=$(BASE)/deps/yara-$(YARA)/build "CFLAGS=-I$(BASE)/deps/file-$(FILE)/build/include -I$(BASE)/deps/zlib-$(ZLIB)/build/include" "LDFLAGS=-L$(BASE)/deps/file-$(FILE)/build/lib -L$(BASE)/deps/zlib-$(ZLIB)/build/lib"
	cd $(BASE)/deps/yara-$(YARA) && make
	cd $(BASE)/deps/yara-$(YARA) && make install
