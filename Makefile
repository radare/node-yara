
BASE=$(shell pwd)

YARA=3.5.0

libyara: yara

yara:
	-rm -rf $(BASE)/deps/yara-$(YARA)
	cd $(BASE)/deps && tar -xzvf yara-$(YARA).tar.gz
	cd $(BASE)/deps/yara-$(YARA) && ./bootstrap.sh
	cd $(BASE)/deps/yara-$(YARA) && ./configure \
			--enable-static \
			--disable-shared \
			--enable-magic \
			--with-pic \
			--with-crypto \
			--prefix=$(BASE)/deps/yara-$(YARA)/build
	cd $(BASE)/deps/yara-$(YARA) && make
	cd $(BASE)/deps/yara-$(YARA) && make install
