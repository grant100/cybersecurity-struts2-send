# Commandline Emulator | CVE-2017-5638

# Disclaimer

*This is meant for educational, and research purposes only. I do not authorize or endorse any illegal or unethical use of this projects contents or information*
*Proof of concept command line emulator to deliver payloads for CVE-2017-5638*

# Instructions

* Run: java -jar Send.jar

* Url: http://localhost/Webapp/action

Supports most basic CLI commands. Works by figuring out context path from webserver and translating user commands into that context.

For example the webserver might return a path of 

    /root/webapp/src
    
so a **'cd ..'** command would have to be translated to 

    'cd /root/webapp' 

in the payload and so on.

Intended as a proof of concept, so it isn't perfect, however it does illustrate that it would be easy to start romping throughout a vulnerable webapp