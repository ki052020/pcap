MY_PROG := pcap
MY_SRCS := $(wildcard src/*.cpp)
MY_OBJS := $(MY_SRCS:src/%.cpp=obj/%.o)
MY_INC_PATH := -I /home/docker_shared/boost/boost_1_87_0

# -g : デバッグ用ビルドを実行
# -rdynamic : デバッグ用シンボル名を出力
MY_OPTS := -g -rdynamic -std=c++20 -Wall -Wno-format-security

main:
	rm -f $(MY_PROG)
	$(MAKE) build

# -ldl は、stacktrace 取得のため（OBJ ファイルの後に書くこと）
build: $(MY_OBJS)
	g++-10 $(MY_OPTS) $^ -ldl -lbacktrace -o $(MY_PROG)

# -H : プリコンパイル済みヘッダを利用
# https://www.ochappa.net/posts/pre-c-bs
obj/%.o: src/%.cpp
	g++-10 $(MY_OPTS) $(MY_INC_PATH) -c $< -o $@
#	g++-10 $(MY_OPTS) $(MY_INC_PATH) -H -c $< -o $@

.PHONY: clean
clean:
	@rm -f $(MY_PROG) obj/*

%:
	$(eval S := src/$@.cpp)
	$(eval O := obj/$@.o)
	g++-10 $(MY_OPTS) -c $S -o $O

