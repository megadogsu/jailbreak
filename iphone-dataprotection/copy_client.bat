@echo off
start /B tcprelay.bat
winscp /script=copy_client.txt
plink -ssh localhost -l root -pw alpine -P 2222