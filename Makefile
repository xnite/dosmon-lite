include /usr/local/etc/PcapPlusPlus.mk

all:
	@echo "Building DOSMon+"
	@if [ ! -d "build/" ]; then mkdir build; fi
	g++ $(PCAPPP_INCLUDES) -c -o build/dosmon.o src/dosmon.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/dosmon build/dosmon.o $(PCAPPP_LIBS)
	@echo "Cleaning up..."
	rm build/*.o
test:
	@echo "Building test files"
	@if [ ! -d "build/" ]; then mkdir build; fi
	g++ $(PCAPPP_INCLUDES) -c -o build/test.o src/test.cpp
	g++ $(PCAPPP_LIBS_DIR) -static-libstdc++ -o build/test build/test.o $(PCAPPP_LIBS)
clean:
	@echo 'Cleaning up files.'
	rm -rf build/
install:
	@if [ ! -d "/var/log/dosmon" ]; then mkdir /var/log/dosmon; fi
	cp ./build/dosmon /sbin/dosmon