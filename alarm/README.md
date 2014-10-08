Macgill Davis

1. I believe that everything has been implemented correctly. However, when Aansh Kapadia and I null scanned and Xmas scanned each other using nmap our alarms did not work. However I built a null and xmas tree TCP packet and my program worked. For some reason the nmap was not Xmas or Null scanning correctly. When we printed out the flags from the null and xmas scans the flags were not set accordingly. I wrote a test program that shows that the null and xmas technique works correctly. It is commented out right now but if you uncomment you it in main it will run.

2. Aansh Kapadia

3. 6 hours


QUESTIONS

1. These heuristics are not that good because they are going to lead to a lot of false positives. When running the live_stream of the alarm, you see that a lot of packet data sets of the credit card alarm. Similarly when looking for shellcode the alarm will sound for a lot of data that is not actually shellcode.

2. I might add scanning the paylod for key words like "credit" "card" "money." I think that it might be helpful to give a 'score' to certain packets. For example, if a packet has credit card numbers and has the word "credit" in the payload, that would have a high score. But if the packet has the credit card numbers only, with no '-' in between that would be a lower score although still set off the alarm. 