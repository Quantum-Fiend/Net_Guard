cmake_minimum_required(VERSION 3.16)
project(NetGuard_Core VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

if(MSVC)
    add_compile_options(/W4 /O2 /MP)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -O2)
endif()

# Npcap SDK
set(NPCAP_SDK_DIR "C:/npcap-sdk" CACHE PATH "Path to Npcap SDK")
if(EXISTS "${NPCAP_SDK_DIR}/Include")
    set(PCAP_INCLUDE_DIR "${NPCAP_SDK_DIR}/Include")
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(PCAP_LIBRARY_DIR "${NPCAP_SDK_DIR}/Lib/x64")
    else()
        set(PCAP_LIBRARY_DIR "${NPCAP_SDK_DIR}/Lib")
    endif()
endif()

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${PCAP_INCLUDE_DIR})

set(SOURCES
    src/packet_capture.c
    src/protocol_parser.c
    src/ring_buffer.c
    src/memory_pool.c
    src/flow_tracker.c
    src/detection_engine.c
    src/tls_fingerprint.c
    src/ipc_bridge.c
)

add_library(netguard_core SHARED ${SOURCES})
target_compile_definitions(netguard_core PRIVATE NETGUARD_EXPORTS)
target_link_directories(netguard_core PRIVATE ${PCAP_LIBRARY_DIR})
target_link_libraries(netguard_core wpcap ws2_32 iphlpapi)

install(TARGETS netguard_core RUNTIME DESTINATION bin LIBRARY DESTINATION lib)
install(FILES include/netguard_core.h DESTINATION include)
