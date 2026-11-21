cmake_minimum_required(VERSION 3.20)
project(TvCasMac LANGUAGES CXX OBJCXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_OBJCXX_STANDARD 20)
set(CMAKE_OBJCXX_STANDARD_REQUIRED ON)

add_library(tvcas_b25 STATIC
    Multi2DecoderMac.cpp
    CardReaderMac.mm
    CasCardMac.cpp
    TSDescramblerMac.cpp
    TVTestCasBridge.mm
)

target_include_directories(tvcas_b25 PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
)

target_compile_options(tvcas_b25 PRIVATE
    -Wall
    -Wextra
    $<$<COMPILE_LANGUAGE:OBJCXX>:-fobjc-arc>
)

target_link_libraries(tvcas_b25 PUBLIC
    "-framework Foundation"
    "-framework PCSC"
)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()

    add_executable(TvCasTests
        TvCasTests.mm
    )
    target_compile_options(TvCasTests PRIVATE
        -Wall
        -Wextra
        -fobjc-arc
    )
    target_link_libraries(TvCasTests PRIVATE
        tvcas_b25
    )
    add_test(NAME TvCasTests COMMAND TvCasTests)
endif()
