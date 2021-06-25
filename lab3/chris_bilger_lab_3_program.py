#!/usr/bin/env python3

import re
import subprocess

def main():
    known_sources = {}
    known_blocked = {}

    while (True):
        p = subprocess.Popen("ovs-ofctl dump-flows s1", shell=True, stderr=subprocess.STDOUT, stdout=subprocess.PIPE)
        pp = p.stdout.read().decode("utf-8")
    
        if "s1 is not a bridge or a socket" in pp:
            continue

        #print(pp)

        pp = pp.strip(" \t\n\r")
        pp = pp.split(",")
    
        #print(pp)

        dl_src = None
        nw_src = None

        for response_param in pp:
            if response_param.startswith("dl_src="):
                dl_src = response_param.split("=")[1]
            elif response_param.startswith("nw_src="):
                nw_src = response_param.split("=")[1]

        if dl_src is None or nw_src is None:
            continue

        #print(dl_src, nw_src)

        if known_sources.get(dl_src, None) is None:
            known_sources[dl_src] = nw_src
        elif known_sources.get(dl_src) != nw_src:
            string_to_write = "1," + dl_src + ",00:00:00:00:00:02,any,any,any,any,any\n"

            if known_blocked.get(dl_src, None) is None:
                known_blocked[dl_src] = True
            else:
                continue

            with open("/home/ubuntu/pox/l3firewall.config", "a") as firewall_config_file:
                firewall_config_file.write(string_to_write)

if __name__ == "__main__":
    main()
