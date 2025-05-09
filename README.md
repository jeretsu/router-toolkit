# router-toolkit
Archive version of routertoolkit

Routertoolkit was created for research purposes of automating router testing and certification. Routertoolkit was a script that ran a collection of selected Open-Source Programs.
Refinement of the toolkit ended as soon as it got the job done so many questionable design choices remain for you to wonder.
I would not recommend trying to get this to work on your machine.

Original idea was to create an automatic tool for users to test their routers against common threats such as vulnerabilities, misconfigurations and open ports.
Users could verify the validity of IoT-security certificates according to three specifications (BSI-Router-Spec, Cybersecurity-Labelling-Scheme-Tier4, Tietoturvamerkki).
Open-Source programs were heavily utilized to cover testcases from before mentioned test specifications. Originally all programs were meant to be ran using Docker but 
later also subprocess was utilized. Toolkit took information from a config file that the user had to manually fill beforehand. Toolkit would create a logfile that had to be
manually inspected by the user to determine the outcome of the tests.

Open-Source programs that were utilized
+ Nmap
+ wifite2
+ Dirbuster
+ testssl.sh
+ Routersploit
+ Zed Attack Proxy
