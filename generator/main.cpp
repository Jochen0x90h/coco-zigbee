#include <coco/crypt.hpp>
#include <coco/hash.hpp>
#include <coco/zigbee.hpp>
#include <iostream>
#include <iomanip>


using namespace coco;

// print tinycrypt aes key
void printKey(char const *name, AesKey const &key) {
	std::cout << "AesKey const " << name << " = {{";
	bool first = true;
	for (auto w : key.words) {
		if (!first)
			std::cout << ", ";
		first = false;
		std::cout << "0x" << std::hex << std::setfill('0') << std::setw(8) << w;
	}
	std::cout << "}};" << std::endl << std::endl;
}

// generate zbee keys for use with tinycrypt
void generateZa09Keys() {
	AesKey aesKey;

	// link key
	setKey(aesKey, zigbee::za09LinkKey);
	printKey("za09LinkAesKey", aesKey);

	// transport key
	DataBuffer<16> hashedKey;
	keyHash(hashedKey, zigbee::za09LinkKey, 0);
	setKey(aesKey, hashedKey);
	printKey("za09KeyTransportAesKey", aesKey);

	// key load key
	keyHash(hashedKey, zigbee::za09LinkKey, 2);
	setKey(aesKey, hashedKey);
	printKey("za09KeyLoadAesKey", aesKey);
}


int main(int argc, const char **argv) {
	// generate keys for coco/zigbee.cpp
	generateZa09Keys();

	return 0;
}
