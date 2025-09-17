# Offensive CyberSecurity CLI Toolkit

## Notes for Windows use

- Install Npcap on windows and enable "WinPcap API-compatible mode" during install
    <https://nmap.org/npcap/>
- Run as Administartor

## to run hash cracker

1. make the wordlist (a curated wordlist for this or skip this if u have the classic rockyou.txt)

``` bash
    python make_wordlist.py
```

2. make an test hash from the above make_wordlist.py script (or if using the ur own wordlist just skip this)

``` bash
    python make_hashes.py
```

## time wasted

- packet sniffer - 6 hrs
- port and vulnerbility scanner - 3 hrs
- hash cracker + making hashes and wordlist - 5hrs
