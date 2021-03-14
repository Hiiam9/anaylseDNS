all:
	gcc pcap_analyse.c -o analyse
clean:
	rm -rf analyse
