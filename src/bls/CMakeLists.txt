cmake_minimum_required (VERSION 2.6)
project(bls CXX ASM C)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

set(LIBS mcl gmp)

option(
	BLS_ETH
	"Ethereum 2.0 spec"
	"OFF"
)

if(BLS_ETH)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DBLS_ETH")
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")

if(MSVC)
    if(MSVC_RUNTIME_DLL)
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} /MD /W4 /Oy /Ox /EHsc /GS- /Zi /DNDEBUG /DNOMINMAX")
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /MDd /W4 /DNOMINMAX")
    else()
		set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS} /MT /W4 /Oy /Ox /EHsc /GS- /Zi /DNDEBUG /DNOMINMAX")
	    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS} /MTd /W4 /DNOMINMAX")
    endif()
else()
	if("${CFLAGS_OPT_USER}" STREQUAL "")
		set(CFLAGS_OPT_USER "-O3 -DNDEBUG -march=native")
	endif()
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wformat=2 -Wcast-qual -Wcast-align -Wwrite-strings -Wfloat-equal -Wpointer-arith ${CFLAGS_OPT_USER}")
	set(CMAKE_CXX_FLAGS "${CMAKE_C_FLAGS}")
endif()

include_directories(include/
  ${GMP_INCLUDE_DIR}
  ${CMAKE_CURRENT_SOURCE_DIR}/..
  ${CMAKE_CURRENT_BINARY_DIR}/..
  ${CMAKE_CURRENT_SOURCE_DIR}/mcl/include)

add_subdirectory(mcl)

add_library(bls src/bls_c384.cpp bls_functions.cpp)
target_link_libraries(bls mcl ${GMP_LIBRARY})




