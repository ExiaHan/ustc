icmpRedirect:FORCE
	@clear
	@gcc -o icmpRedirect icmpRedirect.o -lpcap
	@echo -e "CAUTION !!! icmpRedirect need Capability **cap_net_raw+ep**!!"
	@echo -e "So will run SHELL COMMAND"
	@echo -e "********************************************************"
	@echo -e "******sudo setcap cap_net_raw+ep icmpRedirect***********"
	@echo -e "********************************************************"
	@echo -e "This Will Need You Input **PASSWORD of ROOT**"
	sudo setcap cap_net_raw+ep icmpRedirect
	@echo -e "Success!"
	@echo -e "*********************************************************************"
	@echo -e "***USAGE: ./icmpRedirect Interface TargetIP GateWay FakeGateWay******"
	@echo -e "*********************************************************************"
	@echo -e "INFO:You Active Interface List:"
	@echo -e "*********************************************************************"
	@echo -e "*********************************************************************"
	@ifconfig

FORCE:icmpRedirect.c
	@gcc -g -c icmpRedirect.c
