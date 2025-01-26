#!/bin/bash
rm -f pch.h.gch

#g++-10 -std=c++20 pch.h
g++-10 -g -std=c++20 pch.h
