add_library(${PROJECT_NAME})
target_sources(${PROJECT_NAME}
	PUBLIC FILE_SET headers TYPE HEADERS FILES
		crypt.hpp
		CryptReader.hpp
		CryptWriter.hpp
		greenpower.hpp
		hash.hpp
		Nonce.hpp
		zigbee.hpp
		zcl.hpp
		tinycrypt/aes.h
		tinycrypt/constants.h
		tinycrypt/utils.h
	PRIVATE
		crypt.cpp
		hash.cpp
		zigbee.cpp
		tinycrypt/aes_encrypt.c
		tinycrypt/utils.c
)

target_link_libraries(${PROJECT_NAME}
	coco::coco
	coco-device::coco-device
)

target_include_directories(${PROJECT_NAME}
	PUBLIC
		..
)

# install the library
install(TARGETS ${PROJECT_NAME}
	FILE_SET headers DESTINATION include/coco
	FILE_SET platform_headers DESTINATION include
	LIBRARY DESTINATION lib
	ARCHIVE DESTINATION lib
)
