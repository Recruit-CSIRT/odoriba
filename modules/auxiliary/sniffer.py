# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2015 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

# [customized] this module is to capture the packets 
#              additional is a static capture filter. see tab # custom comments

import os
import getpass
import logging
import subprocess

from lib.cuckoo.common.abstracts import Auxiliary
from lib.cuckoo.common.constants import CUCKOO_ROOT, CUCKOO_GUEST_PORT

log = logging.getLogger(__name__)

class Sniffer(Auxiliary):
    def __init__(self):
        Auxiliary.__init__(self)
        self.proc = None

    def start(self):
        if not self.machine.interface:
            log.error("Network interface not defined, network capture aborted")
            return

        # Handle special pcap dumping options.
        if "nictrace" in self.machine.options:
            return

        tcpdump = self.options.get("tcpdump", "/usr/sbin/tcpdump")
        bpf = self.options.get("bpf", "")
        file_path = os.path.join(CUCKOO_ROOT, "storage", "analyses",
                                 "%s" % self.task.id, "dump.pcap")

        if not os.path.exists(tcpdump):
            log.error("Tcpdump does not exist at path \"%s\", network "
                      "capture aborted", tcpdump)
            return

        # TODO: this isn't working. need to fix.
        # mode = os.stat(tcpdump)[stat.ST_MODE]
        # if (mode & stat.S_ISUID) == 0:
        #    log.error("Tcpdump is not accessible from this user, "
        #              "network capture aborted")
        #    return

        pargs = [
            tcpdump, "-U", "-q", "-s", "0", "-n",
            "-i", self.machine.interface,
        ]

        # Trying to save pcap with the same user which cuckoo is running.
        try:
            user = getpass.getuser()
            pargs.extend(["-Z", user])
        except:
            pass

        pargs.extend(["-w", file_path])
        pargs.extend(["host", self.machine.ip])

        # Do not capture XMLRPC agent traffic.
        pargs.extend([
            "and", "not", "(",
            "dst", "host", self.machine.ip, "and",
            "dst", "port", str(CUCKOO_GUEST_PORT),
            ")", "and", "not", "(",
            "src", "host", self.machine.ip, "and",
            "src", "port", str(CUCKOO_GUEST_PORT),
            ")",
        ])

        # Do not capture ResultServer traffic.
        pargs.extend([
            "and", "not", "(",
            "dst", "host", self.machine.resultserver_ip, "and",
            "dst", "port", self.machine.resultserver_port,
            ")", "and", "not", "(",
            "src", "host", self.machine.resultserver_ip, "and",
            "src", "port", self.machine.resultserver_port,
            ")",
        ])

        #########  custom  exclusive normal traffic from ###
        ## add your own normal traffic which is not needed.
        ####################################################

        # Do not capture Default ICMP
        ICMP="Write your own"
        pargs.extend([
            "and", "not", "(",
            "dst", "host", self.machine.ip, "and",
            "src", "host", ICMP, "and",
            "icmp"
            ")", 
        ])
    
        
        # Do not capture Cetrificates ,
        pargs.extend([
            "and", "not", "(",
            "dst", "host", "117.18.237.29", "and",   
            "dst", "port", "80",
            ")", "and", "not", "(",
            "src", "host", "117.18.237.29", "and",
            "src", "port", "80",
            ")",
        ]) #ocsp.digicert.com
        pargs.extend([
            "and", "not", "(",
            "dst", "host", "72.21.91.29", "and",   
            "dst", "port", "80",
            ")", "and", "not", "(",
            "src", "host", "72.21.91.29", "and",
            "src", "port", "80",
            ")",
        ]) #ocsp.digicert.com 2tcudpm
        pargs.extend([
            "and", "not", "(",
            "dst", "host", "178.255.83.1", "and",   
            "dst", "port", "80",
            ")", "and", "not", "(",
            "src", "host", "178.255.83.1", "and",
            "src", "port", "80",
            ")",
        ]) #ocsp.comodoca.com
        pargs.extend([
            "and", "not", "(",
            "dst", "host", "198.41.214.187", "and",   
            "dst", "port", "80",
            ")", "and", "not", "(",
            "src", "host", "198.41.214.187", "and",
            "src", "port", "80",
            ")", 
        ]) #ocsp.msocsp.com
        pargs.extend([
            "and", "not", "(",     
            "dst", "host", "23.59.139.27", "and",   
            "dst", "port", "80",
            ")", "and", "not", "(",
            "src", "host", "23.59.139.27", "and",
            "src", "port", "80",
            ")",   
        ]) #ocsp.verisign.com etc. symcd.com
        pargs.extend([
            "and", "not", "(",     
            "dst", "host", "224.0.0.252", "and", 
            "dst", "port", "5355", "and",
            "udp",
            ")",                          
        ])  # UDP control traffic 
        
        # please add your own normal traffic ..

        ######### to ########################################################################################
 

        if bpf:
            pargs.extend(["and", "(", bpf, ")"])

        try:
            self.proc = subprocess.Popen(pargs)
        except (OSError, ValueError):
            log.exception(
                "Failed to start sniffer (interface=%s, host=%s, pcap=%s)",
                self.machine.interface, self.machine.ip, file_path,
            )
            return

        log.info(
            "Started sniffer with PID %d (interface=%s, host=%s, pcap=%s)",
            self.proc.pid, self.machine.interface, self.machine.ip, file_path,
        )

    def stop(self):
        """Stop sniffing.
        @return: operation status.
        """
        if self.proc and not self.proc.poll():
            try:
                self.proc.terminate()
            except:
                try:
                    if not self.proc.poll():
                        log.debug("Killing sniffer")
                        self.proc.kill()
                except OSError as e:
                    log.debug("Error killing sniffer: %s. Continue", e)
                    pass
                except Exception as e:
                    log.exception("Unable to stop the sniffer with pid %d: %s",
                                  self.proc.pid, e)
