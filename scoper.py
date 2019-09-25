#!/usr/bin/env python
# By Mike Kelly
# exfil.co
# @lixmk


# TODO: Upper to Lower All output
# TODO: Remove ISP Domains via isp list vs current method
# TODO: Parse out Zone Transfer alerts from fierce
# TODO: Add logging functionality
# TODO: Add extra output option to save all results from each test (ie: Crt.sh pages, bing pages, etc)
# TODO: Remove "Bing Error on" Output, it's useless

import argparse
import re
import subprocess
import os
import shutil
import urllib2
import ssl
import sys
import socket
import masscan
import M2Crypto
from netaddr import IPNetwork
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from cidrize import cidrize

# Global declairations. Some of this may not need to be global, but if it works, it works
cidrs = []              # Input file parsed
parserr = []            # Errored parsing IPs
scope = []              # Individual IPs in scope
synack = []             # Holder for Synack Scope
nmapscope = []          # Used to break up scope into digestible sizes
nmaphostnames = []      # Hostnames discovered by Nmap
fiercetargets = []      # domains and subdomains for fierce targeting. Derived from nmaphostnames
fiercehostnames = []    # Hostnames discovered by Fierce
crtshurls = []          # List of fully developed URLs for crt.sh, Developed from nmaphostnames
crthostnames = []       # Hostnames discovered by crt.sh
crtfound = []           # Found by crt.sh to be resolve (
scopehostnames = []     # Parsed list of all inscope hostnames
argdomains = []         # Additional domains to search
binghostnames = []      # Hostnames discovered via Bing IP search
masscope = []           # Target IPs to give to masscan, broken down into 256 IP chunks
masshosts = []          # Inital masscan ips with 443 open
masshostnames = []      # discovered hostnames
fullpath = ""           # Output path, default ./scoper
ccodes = ['ac','ad','ae','af','ag','ai','al','am','an','ao','aq','ar','as','at','au','aw','ax','az','ba','bb','bd','be','bf','bg','bh','bi','bj','bl','bm','bn','bo','bq','br','bs','bt','bv','bw','by','bz','ca','cc','cd','cf','cg','ch','ci','ck','cl','cm','cn','co','cr','cu','cv','cw','cx','cy','cz','de','dj','dk','dm','do','dz','ec','ee','eg','eh','er','es','et','eu','fi','fj','fk','fm','fo','fr','ga','gb','gd','ge','gf','gg','gh','gi','gl','gm','gn','gp','gq','gr','gs','gt','gu','gw','gy','hk','hm','hn','hr','ht','hu','id','ie','il','im','in','io','iq','ir','is','it','je','jm','jo','jp','ke','kg','kh','ki','km','kn','kp','kr','kw','ky','kz','la','lb','lc','li','lk','lr','ls','lt','lu','lv','ly','ma','mc','md','me','mf','mg','mh','mk','ml','mm','mn','mo','mp','mq','mr','ms','mt','mu','mv','mw','mx','my','mz','na','nc','ne','nf','ng','ni','nl','no','np','nr','nu','nz','om','pa','pe','pf','pg','ph','pk','pl','pm','pn','pr','ps','pt','pw','py','qa','re','ro','rs','ru','rw','sa','sb','sc','sd','se','sg','sh','si','sj','sk','sl','sm','sn','so','sr','ss','st','su','sv','sx','sy','sz','tc','td','tf','tg','th','tj','tk','tl','tm','tn','to','tp','tr','tt','tv','tw','tz','ua','ug','uk','um','us','uy','uz','va','vc','ve','vg','vi','vn','vu','wf','ws','yt','za','zm','zw']
isps = [] # NEED TO DO THIS

# Colorize output stuff
mods = "\033[1m\033[97m[=] "
mode = "\033[0m"
good = "\033[1m\033[32m[+]\033[0m "
stat = "\033[1m\033[34m[*]\033[0m "
warn = "\033[1m\033[91m[!]\033[0m "

# Print silly banner
def printtitle():
    print "" 
    print "\033[1m\033[91m##############################################\033[0m"
    print "\033[1m\033[91m= = =\033[0m                                    \033[1m\033[91m= = =\033[0m"
    print "\033[1m\033[91m= = =\033[0m \033[1m\033[97m   Scoper (TM) scope enumerator   \033[0m \033[1m\033[91m= = =\033[0m"
    print "\033[1m\033[91m= = =\033[0m              \033[1m\033[97mBy lixmk\033[0m              \033[1m\033[91m= = =\033[0m"
    print "\033[1m\033[91m= = =\033[0m                                    \033[1m\033[91m= = =\033[0m"
    print "\033[1m\033[91m##############################################\033[0m"
    print ""

# Parse input file, Synack C/P
def parse_synack():
    print stat+"Parsing input file"
    with open(filein) as f:
        lines = f.readlines()
        for line in lines:
            cidrlines = re.findall('[0-9]{1,3}?\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}/[0-9]{1,2}',line)
            for cidr in cidrlines:
                synack.append(cidr)
    for iprange in synack:
        for ip in IPNetwork(iprange):
            if str(ip) not in scope:
                scope.append(str(ip))
            with open(fullpath+"inscope-ips.txt","a+") as f:
                f.write(str(ip)+'\n')
    print good+"Total in scope IP addresses: "+str(len(scope))
    return scope


# Parse input file
def parse_scope():
    timewarn = 0
    print stat+"Parsing input file to CIDR ranges"
    with open(filein) as f:
        lines = f.readlines()
        for line in lines:
            if '-' in line:
                if line.split("-")[0] == line.split("-")[1].rstrip():
                    line = line.split("-")[0]
            try:
                cidrfound = str(cidrize(line)).split("'")[1]
                cidrs.append(cidrfound)
            except:
                parserr.append(line)
                pass
    if len(parserr) > 0:
        print warn+"Error parsing the following lines:"
        for line in parserr:
            print "    "+line.rstrip()
    print stat+"Parsing CIDR ranges to IP addresses"
    for cidr in cidrs:
        if timewarn == 0 and int(cidr.split('/')[1]) < 17:
            print warn+"One or more large ranges (/16+) detected"
            print warn+"This is not a problem, but may take additional time to parse"
            timewarn = 1
        for ip in IPNetwork(cidr):
            if str(ip) not in scope:
                scope.append(str(ip))
            with open(fullpath+"inscope-ips.txt","a+") as f:
                f.write(str(ip)+'\n')
    print good+"Total in scope IP addresses: "+str(len(scope))
    return scope

# Add arg domains for crt.sh and fierce
def adddomains():
    print stat+"Adding Custom Domains"
    for domain in re.split('\,', domains):
        argdomains.append(domain)
        print stat+"    "+domain
    return argdomains

# Nmap reverse DNS 
def nmapresolve():
    ipcount = len(scope)
    print stat+"Executing Nmap Reverse Lookup against "+str(ipcount)+" total IPs"
    print stat+"Breaking IPs into digestible parts (<=4096)"
    if ipcount > 4096:
        for part in range(0, ipcount, 4096):
            nmapscope.append(scope[part:part + 4096])
    else:
        nmapscope.append(scope)
    nmapcount = len(nmapscope)
    print stat+"IPs broken into "+str(nmapcount)+" parts"
    count = 0
    for targets in nmapscope:
        count += 1
        try:
            sys.stdout.write("\r"+stat+"Executing part "+str(count)+" of "+str(nmapcount))
            sys.stdout.flush()
            nmap = NmapProcess(targets, options="-sL -R")
            rc = nmap.run()
            resolved = NmapParser.parse(nmap.stdout)
            for host in resolved.hosts:
                for hostname in host.hostnames:
                    hostname = hostname.lower()
                    if not re.findall('[0-9]{1,3}?\-[0-9]{1,3}\-[0-9]{1,3}\-[0-9]{1,3}',hostname) and not re.findall('[0-9]{1,3}?\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',hostname) and 'zayo.com' not in hostname and "ip-addr" not in hostname and "Level3" not in hostname and "in-addr" not in hostname and '.' in hostname:
                        nmaphostnames.append((host.address, hostname))
        except (KeyboardInterrupt, SystemExit):
            goodresp = 0
            while goodresp == 0:
                print ""
                resp = raw_input(warn+'Interrupt Caught. Want to kill all Nmap? (y) or this part (n): ')
                if "y" in resp:
                    print warn+"Killing all Nmap parts"
                    return nmaphostnames
                elif "n" in resp:
                    print stat+"Continuing w/ next part"
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
    print ""
    print good+"Nmap lookup complete. Hostnames found: "+str(len(nmaphostnames))
    return nmaphostnames

# Masscan for for 443
def scanmass():
    ipcount = len(scope)
    print stat+"Executing Masscan against "+str(ipcount)+" total IPs"
    print stat+"Breaking IPs into digestible parts (<=4096)"
    if ipcount > 4096:
        for part in range(0,ipcount,4096):
            masscope.append(scope[part:part + 4096])
    else:
        masscope.append(scope)
    partsnumber = len(masscope)
    print stat+"IPs broken into "+str(partsnumber)+" parts"
    partcount = 0
    count = 0
    for part in masscope:
        partcount += 1
        sys.stdout.flush()
        sys.stdout.write("\r"+stat+"Scanning part "+str(partcount)+" of "+str(partsnumber)+" ")
        sys.stdout.flush()
        targets = ",".join(part)
        try:
            mas = masscan.PortScanner()
            mas.scan(targets, ports='443', arguments='--rate=1000')
            for host in mas.all_hosts:
                masshosts.append(host)
                count += 1
            sys.stdout.write("- 443 on: "+str(count))
            sys.stdout.flush()
        except (masscan.masscan.NetworkConnectionError):
            sys.stdout.write("- 443 on: "+str(count))
            sys.stdout.flush()
            pass
        except (KeyboardInterrupt, SystemExit):
            goodresp = 0
            while goodresp == 0:
                print ""
                resp = raw_input(warn+'Interrupt Caught. Want to kill all Massscan? (y) or this chunk (n): ')
                if "y" in resp:
                    print warn+"Killing all Masscan parts"
                    return masshosts
                elif "n" in resp:
                    print stat+"Continuing with next part"
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
    print ""
    print good+"Masscan complete. Total hosts with 443 open: "+str(count)
    return masshosts

# Parse masscan results and pull CN + subjectAltNames
def parsemass():
    ipnumber = len(masshosts)
    ipcount = 0
    if ipnumber > 0:
        for ip in masshosts:
            ipcount += 1
            sys.stdout.flush()
            sys.stdout.write("\r"+stat+"Checking for hostnames from SSL cert on IP "+str(ipcount)+" of "+str(ipnumber))
            sys.stdout.flush()
            try:
                socket.setdefaulttimeout(10)
                cert = ssl.get_server_certificate((ip, 443))
                x509 = M2Crypto.X509.load_cert_string(cert)
                cert_sub = x509.get_subject().as_text()
                cname = re.sub(r'\s+', '', str(cert_sub.split('CN=')[1]).lower())
                if '/' in cname:
                    cname = re.split('/', cname)[0]
                if ',' in cname:
                    cname = re.split(',', cname)[0]
                if len(cname) > 0 and (ip, cname) not in masshostnames and '*' not in cname and ':' not in cname and '.' in cname:
                    namesplit = re.split('\.',cname)
                    subnum = int(len(namesplit) - 1)
                    if namesplit[subnum].isdigit() == False:
                        masshostnames.append((ip, cname))
                cert_ext = str(re.sub('DNS:', '', x509.get_ext("subjectAltName").get_value())).split(', ')
                for name in cert_ext:
                    name = re.sub(r'\s+', '', name.lower())
                    if '/' in name:
                        name = re.split('/', name)[0]
                    if ',' in name:
                        name = re.split(',', name)[0]
                    if (ip, name) not in masshostnames and '*' not in name and ':' not in name and '.' in name:
                        namesplit = re.split('\.',name)
                        subnum = int(len(namesplit) - 1)
                        if namesplit[subnum].isdigit() == False:
                            masshostnames.append((ip, name))
            except (ssl.SSLEOFError, ssl.SSLError, socket.error, LookupError):
                pass
            except (KeyboardInterrupt, SystemExit):
                print ""
                goodresp = 0
                while goodresp == 0:
                    resp = raw_input(warn+'Interrupt Caught. Want to kill all cert checks? (y|n): ')
                    if "y" in resp:
                        print warn+"Killing all cert checks"
                        return masshostnames
                    elif "n" in resp:
                        print stat+"Continuing cert checks"
                        goodresp = 1
                    else:
                        print warn+"Invalid Option..."
        print "\n"+good+"Hostname check complete. Hostnames found: "+str(len(masshostnames))
    else:
        print warn+"Masscan found no hosts with 443 open :("
    return masshostnames

# Search Bing for IP Addresses to discover hostnames
def bingip():
    print stat+"Executing Bing IP search"
    bingcount = len(scope)
    count=0
    for ip in scope:
        count +=1
        sys.stdout.flush()
        sys.stdout.write("\r"+stat+"   IP "+str(count)+" of "+str(bingcount))
        sys.stdout.flush()
        bingurl = "http://www.bing.com/search?q=ip%3A"+ip
        crthostcount = 0
        sslcontext = ssl.create_default_context()
        sslcontext.check_hostname=False
        sslcontext.verify_mode = ssl.CERT_NONE
        # Get results
        try:
            datarecv = urllib2.urlopen(bingurl, context=sslcontext)
            datatext = datarecv.readlines()
            if '<h1>There are no results for <strong>' not in datatext:
                for line in datatext:
                    if "Search Results" in line and "People also ask" not in line and 'bing.com' not in line:
                        cleanlines = re.split('\n', re.sub('</cite>', '\n', re.sub('<cite>', '\n', line)))
                        for newline in cleanlines:
                            nostrong = re.sub('</strong>', '', re.sub("<strong>", '', newline))
                            if '>' not in nostrong and '.' in nostrong:
                                hostname = str(re.split('/', re.sub('https://', '', nostrong))[0]).lower()
                                if (ip, hostname) not in binghostnames:
                                    binghostnames.append((ip, hostname))
                                    with open(fullpath+"bingfound.txt","a+") as f:
                                        f.write(ip+" - "+hostname+"\n")
        except (KeyboardInterrupt, SystemExit):
            print ""
            goodresp = 0
            while goodresp == 0:
                resp = raw_input(warn+'Interrupt Caught. Want to kill Bing Search? (y|n): ')
                if "y" in resp:
                    print warn+"Killing all Bing searches"
                    return binghostnames
                elif "n" in resp:
                    print stat+"Continuing Bing searches"
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
        except:
            pass
    print "\n"+good+"Bing IP Search complete. Hosts found: "+str(len(binghostnames))
    return binghostnames

###
# Loop through target domains determined from Nmap output
# Searchs Crt.sh for certs assigned to subdomains of the target domain.
# Then resolves all discovered hostnames for IP addresses
###
def checkcrtsh():
    print stat+"Generating list of targets for crt.sh"
    # Part one: build search URLs, ensure unique
    for host in nmaphostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        crturl = "https://crt.sh/?q=%25."+domain
        if (crturl, domain) not in crtshurls:
            crtshurls.append((crturl, domain))
    for host in masshostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        crturl = "https://crt.sh/?q=%25."+domain
        if (crturl, domain) not in crtshurls:
            crtshurls.append((crturl, domain))
    for host in binghostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        crturl = "https://crt.sh/?q=%25."+domain
        if (crturl, domain) not in crtshurls:
            crtshurls.append((crturl, domain))
    for argdomain in argdomains:
        crturl = "https://crt.sh/?q=%25."+argdomain
        if (crturl, argdomain) not in crtshurls:
            crtshurls.append((crturl, argdomain))
    print good+"Generation Complete. Targeting the following domains: "
    for pair in crtshurls:
        print good+"   "+pair[1]
    for pair in crtshurls:
        sys.stdout.flush()
        sys.stdout.write("\r"+stat+"Checking crt.sh results for: "+pair[1])
        sys.stdout.flush()
        try:
            crthostcount = 0
            datarecv = urllib2.urlopen(pair[0], context=sslcontext)
            dataout = datarecv.readlines()
            # Parse for unique hostnames and save for resolution
            for line in dataout:
                if pair[1] in line and '<TD>' in line:
                    discovered = re.sub('\s+', '', re.sub('<TD>', '', re.sub('</TD>', '', line))).rstrip('\n')
                    if discovered not in crtfound:
                        crthostcount +=1
                        crtfound.append(discovered)
            print " - found: "+str(crthostcount)
        except (KeyboardInterrupt, SystemExit):
            goodresp = 0
            while goodresp == 0:
                print "\n"+warn+"Interrupt Caught"
                resp = raw_input(warn+'Do you want to kill all crt.sh (y|n): ')
                if "y" in resp:
                    print warn+"Killing all crt.sh searches"
                    return crtfound
                    goodresp = 1
                elif "n" in resp:
                    print stat+"Continuing..."
                    break
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
        except socket.gaierror:
            pass
        except:
            print "\n"+warn+"Error on: "+pair[1]
    print good+"Crt.sh search finished. Total hostnames: "+str(len(crtfound))

def resolvecrt():
    print stat+"Resolving hostnames to IP"
    count = 0
    resolvecount = len(crtfound)
    for crthost in crtfound:
        crthost = crthost.lower()
        count +=1
        sys.stdout.flush()
        sys.stdout.write("\r"+stat+"   Host "+str(count)+" of "+str(resolvecount))
        try:
            ip = socket.gethostbyname(crthost.strip())
            if (ip, crthost) not in crthostnames:
                crthostnames.append((ip, crthost))
        except socket.gaierror:
            pass
        except (KeyboardInterrupt, SystemExit):
            goodresp = 0
            while goodresp == 0:
                print "\n"+warn+"Interrupt Caught"
                resp = raw_input(warn+'Do you want to kill all resolution? (y|n): ')
                if "y" in resp:
                    print warn+"Killing all DNS resolution"
                    return crthostnames
                    goodresp = 1
                elif "n" in resp:
                    print stat+"Continuing..."
                    pass
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
    print "\n"+good+"Resolution complete. Hostnames resolved to IP: "+str(len(crthostnames))
    return crthostnames

###
# This simply generates a list of target domains and subdomain for Fierce
# Basically removes the first "octet" of the full host name and checks for uniqueness
###
def genfierce():
    print stat+"Generating target domains/subdomains for fierce"
    for host in nmaphostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        if domain not in fiercetargets:
            fiercetargets.append(domain)
    for host in masshostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        if domain not in fiercetargets:
            fiercetargets.append(domain)
    for host in binghostnames:
        hostsplit = re.split('\.',host[1])
        subnum = int(len(hostsplit) - 1)
        if subnum > 1 and hostsplit[subnum] in ccodes:
            domain = hostsplit[(subnum - 2)]+"."+hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        else:
            domain = hostsplit[(subnum - 1)]+"."+hostsplit[subnum]
        if domain not in fiercetargets:
            fiercetargets.append(domain)
    for argdomain in argdomains:
        if argdomain not in fiercetargets:
            fiercetargets.append(argdomain)
    print good+"Generation Complete. Targeting the following (sub)domains: "
    for target in fiercetargets:
        print good+"   "+target
    return fiercetargets

###
# Loops thorugh targets in fiercetargets and executes runfierce.
###
def execfierce():
    for target in fiercetargets:
        try:
            sys.stdout.flush()
            sys.stdout.write(stat+"Executing fierce against: "+target)
            sys.stdout.flush()
            fierce = ['/usr/bin/fierce', '-dns', target, '-file' ,str(fullpath+"fierce/"+target)]
            p = subprocess.Popen(fierce, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            while(True):
                retcode = p.poll()
                line = p.stdout.readline()
                if retcode is not None:
                    break
                if re.findall('[0-9]{1,3}?\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',line) and "found" not in line:
                    line = re.sub('\s+', ':', line.rstrip('\n'))
                    if '.' in line[1]:
                        fiercehostnames.append((line.split(':')[0], line.split(':')[1].rstrip('\n')))
                if "Found" in line and "entries" in line:
                    found = re.split(' ', line)[1]
                    print " - Found: "+found
        except (KeyboardInterrupt, SystemExit):
            goodresp = 0
            while goodresp == 0:
                print "\n"+warn+"Interrupt Caught"
                resp = raw_input(warn+'Do you want to kill all fierce (y) or just this one (n)?: ')
                if "y" in resp:
                    print warn+"Killing all fierce searchs"
                    return binghostnames
                    goodresp = 1
                elif "n" in resp:
                    print warn+"Killing fierce: "+target
                    goodresp = 1
                else:
                    print warn+"Invalid Option..."
    print good+"Fierce complete"
    return fiercehostnames

# Generate and print results
def resultsout():
    print stat+"Comparing all results to in-scope IPs"
    print stat+"This may take a while depending on number of hostnames found"
    if noscope == 0:
        nmapcount = 0
        for pair in nmaphostnames:
            if pair[0] in scope and pair not in scopehostnames:
                scopehostnames.append(pair)
                nmapcount += 1
        masscount = 0
        for pair in masshostnames:
            if pair[0] in scope and pair not in scopehostnames:
                scopehostnames.append(pair)
                masscount += 1
        bingcount = 0
        for pair in binghostnames:
            if pair[0] in scope and pair not in scopehostnames:
                scopehostnames.append(pair)
                bingcount =+ 1
        crtcount = 0
        for pair in crthostnames:
            if pair[0] in scope and pair not in scopehostnames:
                scopehostnames.append(pair)
                crtcount += 1
        fiercecount = 0
        for pair in fiercehostnames:
            if pair[0] in scope and pair not in scopehostnames:
                scopehostnames.append(pair)
                fiercecount += 1
        for pair in scopehostnames:
            with open(fullpath+"inscope-hostnames.txt","a+") as f:
                f.write(pair[0]+" - "+pair[1].rstrip('.')+'\n')
    if noscope == 1:
        for pair in nmaphostnames:
            if pair not in scopehostnames:
                scopehostnames.append(pair)
                nmapcount += 1
        masscount = 0
        for pair in masshostnames:
            if pair not in scopehostnames:
                scopehostnames.append(pair)
                masscount += 1
        bingcount = 0
        for pair in binghostnames:
            if pair not in scopehostnames:
                scopehostnames.append(pair)
                bingcount =+ 1
        crtcount = 0
        for pair in crthostnames:
            if pair not in scopehostnames:
                scopehostnames.append(pair)
                crtcount += 1
        fiercecount = 0
        for pair in fiercehostnames:
            if pair not in scopehostnames:
                scopehostnames.append(pair)
                fiercecount += 1
        for pair in scopehostnames:
            with open(fullpath+"inscope-hostnames.txt","a+") as f:
                f.write(pair[0]+" - "+pair[1].rstrip('.')+'\n')
    print stat+"Results comparison complete"
    print ""
    print mods+"= = = = = = = = = = = = = = = ="+mode
    print mods+"= = = Scoper(TM) Complete = = ="+mode
    print mods+"= = = = = = = = = = = = = = = ="+mode
    print ""

    print stat+"All output saved to directory "+fullpath
    if fierce:
        print stat+"Raw fierce output in "+fullpath+"fierce/"
    print good+"Total IPs in scope (inscope-ips.txt): "+str(len(scope))
    if nmaprun:
        print stat+"Nmap discovered hostnames: "+str(len(nmaphostnames))
        print good+"Nmap discovered in scope: "+str(nmapcount)
    if mass:
        print stat+"Masscan discovered hostnames: "+str(len(masshostnames))
        print good+"Masscan discovered in scope: "+str(masscount)
    if bing:
        print stat+"Bing discovered hostnames: "+str(len(binghostnames))
        print good+"Bing discovered in scope: "+str(bingcount)
    if crtsh:
        print stat+"Crt.sh discovered hostnames: "+str(len(crthostnames))
        print good+"Crt.sh discovered in scope: "+str(crtcount)
    if fierce:
        print stat+"Fierce discovered hostnames: "+str(len(fiercehostnames))
        print good+"Fierce discovered in scope: "+str(fiercecount)
    print good+"Total in-scope hostnames (inscope-hostnames.txt): "+str(len(scopehostnames))

def main():
    printtitle()
    if os.path.isdir(fullpath):
        resp = raw_input(warn+"Directory "+fullpath+" exists. Overwrite? (y|n): ")
        goodresp = 0
        while goodresp == 0:
            if "y" in resp:
                print warn+"Overwriting "+fullpath
                shutil.rmtree(fullpath)
                os.mkdir(fullpath)
                goodresp = 1
            elif "n" in resp:
                print warn+"Not Overwriting... killing scoper.py"
                sys.exit()
            else:
                print warn+"Invalid Option..."
    else:
        os.mkdir(fullpath)
    os.mkdir(fullpath+"/fierce")
    print mods+"= = = IP Parser = = ="+mode
    if synscope == True:
        parse_synack()
    else:
        parse_scope()
    if domains > 0:
        print mods+"= = = Custom Domains = = ="+mode
        adddomains()
    if nmaprun:
        print mods+"= = = Nmap Rev Lookup = = ="+mode
        nmapresolve()
    if mass:
        print mods+"= = = Masscan + Cert grab = = ="+mode
        scanmass()
        parsemass()
    if bing:
        print mods+"= = = Bing IP Search = = ="+mode
        bingip()
    if crtsh:
        print mods+"= = = Crt.sh Transperency Search = = ="+mode
        checkcrtsh()
        resolvecrt()
    if fierce:
        print mods+"= = = Fierce DNS Bruteforce = = ="+mode
        genfierce()
        execfierce()
    print mods+"= = = Results Comparison = = ="
    resultsout()

if __name__ == '__main__':
    # Argument parsing
    parser = argparse.ArgumentParser(usage='./scoper.py -i <input_file> -d <custom_domain> -n -m -b -c -f')
    parser.add_argument('-i', '--filein', help="Input file, accepts all cidrize formats")
    parser.add_argument('-d', '--domains', help="Additional domains to search")
    parser.add_argument('-n', '--nmaprun', action='store_true', default=False, help="Use nmap for reverse DNS")
    parser.add_argument('-m', '--mass', action="store_true", default=False, help="masscan for 443 and pull hostnames from certs")
    parser.add_argument('-b', '--bing', action="store_true", default=False, help="Bing IP Search")
    parser.add_argument('-c', '--crtsh', action='store_true', default=False, help="Check crt.sh for associated hostnames")
    parser.add_argument('-f', '--fierce', action='store_true', default=False, help="Execute fierce against discovered (sub)domains")
    parser.add_argument('-t', '--timeout', default=10, help="Socket timeout, default 10")
    parser.add_argument('-o', '--outdir', default="scoper", help="Output directory, relative, no ./ needed")
    parser.add_argument('-a', '--execall', action="store_true", default=False, help="same as -n -m -b -c -f")
    parser.add_argument('-N', '--noscope', action="store_true", default=False, help="Disable scope comparison")
    parser.add_argument('-s', '--synack', action="store_true", default=False, help="Take copy/paste from Synack scope section")
    args = parser.parse_args()
    filein = args.filein
    domains = args.domains
    nmaprun = args.nmaprun
    mass = args.mass
    bing = args.bing
    crtsh = args.crtsh
    fierce = args.fierce
    timeout = args.timeout
    outdir = args.outdir
    execall = args.execall
    noscope = args.noscope
    synscope = args.synack
    if execall:
        nmaprun = True
        mass = True
        bing = True
        crtsh = True
        fierce = True
    fullpath = os.getcwd()+"/"+outdir+"/"
    # Default socket/ssl stuff
    socket.setdefaulttimeout(timeout)
    sslcontext = ssl.create_default_context()
    sslcontext.check_hostname=False
    sslcontext.verify_mode = ssl.CERT_NONE

    main()
