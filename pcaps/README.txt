Macgill Davis
Comp116 Ming
Monday September 16, 2014


1. How many packets are there in this set?
	1503 packets		

2. What protocol was used to transfer files from PC to server?
	FTP

3. Briefly describe why the protocol used to transfer the files is insecure?
	FTP is not encrpyted so you can simply grab the data and keep it. 

4. What is the secure alternative to the protocol used to transfer files?
	SFTP. This is encrypted.

5. What is the IP address of the server?
	67.23.79.113	

6. What was the username and password used to access the server?
	USER: ihackpineapples PASS:rockyou1

7. How many files were transferred from PC to server?
	4

8. What are the names of the files transferred from PC to server?
	BjN-O1hCAAAZbiq.jpg

	BvgT9p2IQAEEoHu.jpg

	BvzjaN-IQAA3XG7.jpg

	smash.txt	

9. Extract all the files that were transferred from PC to server. These files must be part of your submission

-------------------------------------------------------------
10. How many packets are there in this set?
	77882

11. How many plaintext username-password pairs are there in this packet set?
	9
	(1. cisco 185 august23
	 2. cisco 185 anthony7
	 3. cisco 185 allahu
	 4. cisco 185 alannah
	 5. cisco 185 BASKETBALL
	 6. cisco 185 12345d
	 7. cisco 185 122333
	 8. cisco 184 yomama1
	 9. chris@digitalinterlude.com Volrathw69) 	

12. Briefly describe how you found the username-password pairs.
	tcp contains User
	tcp contains Pass	
	telnet contains User	

13. For each of the plaintext username-password pair that you found, identify the protocol used, server IP, the corresponding domain name (e.g., google.com), and port number.
	POP3, 75.126.75.131, @mail.si-sv3231.com, port number is 110
	TELNET, 10.156.15.241, port number is 23,	



14. Of all the plaintext username-password pairs that you found, how many of them are legitimate? That is, the username-password was valid, access successfully granted?
	1 is valid. 


15. How did you verify the successful username-password pairs?

16. What advice would you give to the owners of the username-password pairs that you found so their account information would not be revealed "in-the-clear" in the future?
	Do not use insecure protocols like POP3 or HTTP or FTP. Make sure all your data is secure by using encryption like HTTPS.





















