cmake_minimum_required(VERSION 3.28)
project(UnixCustomTransportLayerClient C)

set(CMAKE_C_STANDARD 11)

add_executable(UnixCustomTransportLayerClient main.c
        dustyns_transport_layer.c network_layer.c)
