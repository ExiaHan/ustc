sniffer:FORCE
	@clear
	@gcc -o sniffer sniffer.o -lpcap
	@echo -e "CAUTION !!! Sniffer need Capability **cap_net_raw+ep**!!"
	@echo -e "So will run SHELL COMMAND"
	@echo -e "********************************************************"
	@echo -e "***********sudo setcap cap_net_raw+ep sniffer***********"
	@echo -e "********************************************************"
	@echo -e "This Will Need You Input **PASSWORD of ROOT**"
	sudo setcap cap_net_raw+ep sniffer
	@echo -e "Success!"
	@echo -e "********************************************************"
	@echo -e "*************USAGE: ./sniffer [interface]***************"
	@echo -e "********************************************************"
	@echo -e "INFO:You Active Interface List:"
	@echo -e "********************************************************"
	@echo -e "********************************************************"
	@ifconfig

FORCE:sniffer.c
	@gcc -c sniffer.c
