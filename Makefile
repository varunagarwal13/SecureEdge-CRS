CC ?= gcc
CLANG ?= clang

.PHONY: demo fuzz clean

demo:
	python3 scripts/run_vertical_slice.py

fuzz:
	$(CLANG) -O1 -g -fsanitize=fuzzer,address,undefined -Itargets targets/edge_mqtt_parser.c targets/harness_libfuzzer.c -o /tmp/edge_mqtt_fuzzer
	/tmp/edge_mqtt_fuzzer -max_total_time=15

clean:
	rm -rf outputs /tmp/edge_mqtt_fuzzer
