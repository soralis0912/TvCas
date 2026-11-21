BUILD_DIR ?= build

.PHONY: all build test clean

all: build

build:
	cmake -S . -B $(BUILD_DIR) -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR) --parallel

test: build
	$(BUILD_DIR)/TvCasTests

clean:
	rm -rf $(BUILD_DIR)
