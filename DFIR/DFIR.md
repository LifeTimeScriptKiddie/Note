1. Computer Memory
2. Paging
	1. The paging file contains data which isn’t backed by the disk (i.e., is not an executable or DLL). This includes user data, documents, and malicious programs.

3. Firewire: Firewire is Direct Memory Access. When the protocol was developed, the goal was to allow Firewire devices to read and write directly to main memory without going through the operating system
4. USB devices can use Direct Memory Access, but can't initiate tranfer on their own. 
	1. Tool: Inception
5.

# Overall Process
1. Capture memory image
	1. Create a raw memory dump using WinPmem
		1. `winpmem.exe win7 img.`
	2. Check integrity of memory image by identifying system profile
		1. `vol.py -f win7.img imageinfo`

## Static Properties Analysis
svchost.exe
lsass.exe
	1.FIle and section hashes
	2. Packer identification
	3. Embedded resources
	4. Imports and exports 
	5. Cryto references
	6. Section names
	7. Certificates
	8. Strings
	Tools
		strings -a brbbot.exe |more
		pescanner
		signrch
		virustotal
		Pescan
		MASTIFF
		Exiftool
		AnalyzePESig
		Pyew
		

## Behavior Analysis Process
1. Activate Monitoring tools
	1. process hacker
	2. regshot
	3. CaptureBAT
	4. ProcDOT
	5. process monitor
	6. TcpLogView
	7. Wireshark
	8. nc
2. Run malware on a lab system
3. Terminate the malicious process if you can after a while
4. Pause Monitoring tools
5. Examine Logs for anomlies and other events of interest 

## Code analysis
1. Disassembler and debugger
	1. IDA Pro and OllyDbg
	2. Immunity Debugger
	3. Ghidra, Windbg

## Virtual Machine ENV
1. REMnux
	
