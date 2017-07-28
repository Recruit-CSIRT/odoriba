Odoriba 
====
<hr />
A kind of Malware Dynamic Analysis Platform enhanced Cuckoo Sandbox 2.0-rc1 written in Python2.
<hr />

## Description  
the deep customized sandbox system for CSIRT.   
* Customized dynamic agent for malwares to behave more active in our workplace environment.  
* Analyze C&C servers automatically in terms of capability of Block.   
* you can install AntiVirus software to GuestVM.  
Operation Check :   
	Guest VM : Windows7 x86  
	Host OS: OSX 10  
  
The background and details was presented in FIRST TC Amusterdam 2017   
https://www.first.org/events/colloquia/amsterdam2017/program#precruit-csirt  

## Demo
// Under Construction  

## Comparison Cuckoo Sandbox  
[Cuckoo Sandbox 2.0 rc1](https://cuckoosandbox.org/2016-01-21-cuckoo-sandbox-20-rc1.html) 

**Odoriba's Difference** 
* Real-­time Visualization the analyzed behavior on Web UI.  
* 100MB over Huge File Submittion  
* Collect malwares Malwr(does't work now) or FireEye AX and auto submit  

*Modified Script Files from Cuckoo Sandbox default*  
* [./agents/agent.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/agent/http/agent.pyw)    
* [./lib/cuckoo/core/guest.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/lib/cuckoo/core/guest.py)   
* [./modules/auxiliary/sniffer.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/modules/auxiliary/sniffer.py)   
* [./web/analysis/urls.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/urls.py)   
* [./web/analysis/views.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/views.py)   
* [./web/web/local_settings.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/web/local_settings.py)   

and Configuration Files [./conf/](https://github.com/Recruit-CSIRT/odoriba/blob/master/conf)   


*Created Script Files by Recruit-CSIRT*  
* [./child.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/child.py)  
* [./dl_mal_AXui.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/dl_mal_AXui.py)    
* [./internet_control.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/internet_control.py)    
* [./kill_children.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/kill_children.py)  
* [./malwr_dl.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/malwr_dl.py)  
* [./mylogfunc.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/mylogfunc.py)  
* [./odoriba.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/odoriba.py) 

* [./web/analysis/realview_analyzer.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/realview_analyzer.py)      
* [./web/analysis/bson_dump.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/bson_dump.py)    
* [./web/analysis/pcap_dump.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/pcap_dump.py)    
* [./web/analysis/cymru.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/cymru.py)     
* [./web/analysis/http_access.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/http_access.py)       
* [./web/analysis/virustotal.py](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/analysis/virustotal.py)  
 

*Created For Realtime View*  
* [./web/analysis/templates/analysis/running.html](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/templates/analysis/running.html)  
* [./web/analysis/templates/analysis/finish.html](https://github.com/Recruit-CSIRT/odoriba/blob/master/web/templates/analysis/finish.html)  

## Requirements
* [Cuckoo sandbox requirements](http://docs.cuckoosandbox.org/en/latest/introduction/sandboxing/) is necessary.  
In Addition, python modules  
* requests, selenium webdriver, BeautifulSoup, InsecureRequestWarning  

## Usage
change network signitures in several python codes : your **IP**, **user-agent** etc, modify **"Write your own"** values.    
In your UNIX Host machine (ex. OSX),   
`$ cd ~`  
`$ git clone https://github.com/Recruit-CSIRT/odoriba.git`  

set your Guest Machine configuration in ./conf/
set your Guest IP in ./internet_control.py (this modules support VirtualBox and VMware)

<python 2.7.x>   
`$ python odoriba.py [vmware or virtualbox] [add or init or none] [malwr or ax or none]`  
// sys.argv[1] = GUEST VM environment , odoriba support vmware or virtualbox  
// sys.argv[2] = Setting options  
*init = cuckoo have't launched yet.*    
*add = cuckoo launched and add malware seeds via sys.argv[3]*    
*none = cuckoo launched and skip add seeds*    
//sys.argv[3] = Where malware download from   
*malwr = malwr's recent analysis samples* **Malwr implemented Google reCAPTCHA, this option doesn't work now.**   
*ax = your FireEye AX*     
*none = skip download and you can submit manually*      

if you batch collect malware seeds, set cron this procedure.  
 `$ python odoriba.py [vmware or virtualbox] add [malwr or ax]`  

After Cuckoo Sandbox start working, you can submit files and urls to cuckoo's submit page.   

## Install
[Install Example](https://github.com/Recruit-CSIRT/odoriba/blob/master/Cuckoo_Odoriba_Install.txt)      
  OR   
Install Cuckoo Sandbox and replace the above **[Modified and Created Files]**  in the cuckoo folder.  
If you find some errors , please handle by yourself at first.  
Some error may happen because your working directory name still **cuckoo** ,   
please change to **odoriba** or modify odoriba's source code by yourself.  


*Recruit-CSIRT does not assume any responsibility about using odoriba.*    

**you can take advantage on Self-responsibility**

## Licence
[GPLv3](https://github.com/Recruit-CSIRT/odoriba/blob/master/docs/LICENSE)  

## Author
Tatsuya Ichida  ([icchida](https://github.com/icchida)) 
Ref: r-csirt  ([r-csirt](https://github.com/r-csirt)) 

