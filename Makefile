
BASE=$(shell pwd)
OSNAME=$(shell uname)

ifeq ($(OSNAME),Darwin)
CFGOPTS+=--disable-magic
CFLAGS+=-I/usr/local/include/node
else
CFGOPTS+=--enable-magic
endif

YARA=3.5.0

libyara: yara

yara:
	-rm -rf $(BASE)/deps/yara-$(YARA)
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz
	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && CFLAGS="$(CFLAGS)" ./configure \
			$(YARA_CFGOPTS) \
			--with-crypto \
			--enable-static \
			--disable-shared \
			--with-pic \
			--prefix=$(BASE)/deps/yara-$(YARA)/build
	cd $(BASE)/deps/yara-$(YARA) && make
	cd $(BASE)/deps/yara-$(YARA) && make install
