include ../../Makefile.include NGHTTP2-VERSION ../../download-files.include
DEPS = ../../Makefile.include NGHTTP2-VERSION Makefile ../../download-files.include \
                        01-all-cmake-version.patch

# configuration settings
CMAKE_OPTIONS=-DENABLE_DEBUG=OFF \
              -DENABLE_FAILMALLOC=OFF \
              -DENABLE_LIB_ONLY=ON \
              -DENABLE_DOC=OFF \
              -DBUILD_STATIC_LIBS=ON \
              -DBUILD_SHARED_LIBS=OFF \
              -DWITH_LIBXML2=OFF

LIBDYLIB=$(PLATFORM)/build/lib/$(BYPRODUCT)

all: .installed-$(PLATFORM)

$(PLATFORM): $(DEPS) | $(TARBALLS_LOCATION)/$(ARCHIVE).$(HASH_TYPE)
	rm -rf $(PLATFORM)/*; mkdir -p $(PLATFORM)/build
	cd $(PLATFORM); $(ARCHIVE_TOOL) $(ARCHIVE_TOOL_FLAGS) $(TARBALLS_LOCATION)/$(ARCHIVE)
	cd $(PLATFORM); patch -p1 -i ../01-all-cmake-version.patch
	cd $(PLATFORM)/build; $(CMAKE) $(CMAKE_OPTIONS) ..

$(LIBDYLIB): $(PLATFORM)
	$(MAKE) -C $(PLATFORM)/build

.installed-$(PLATFORM): $(LIBDYLIB)
	$(MAKE) -C $(PLATFORM)/build install
	touch $@

clean:
	$(MAKE) -C $(PLATFORM)/build clean
	rm -f .installed-$(PLATFORM)

distclean::
	rm -rf $(PLATFORM) .installed-$(PLATFORM)
