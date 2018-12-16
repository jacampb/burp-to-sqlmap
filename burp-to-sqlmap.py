try:
    import os
    from bs4 import BeautifulSoup
    import os.path
    import argparse
    import sys
    import codecs

except ImportError:
    print "[!] wrong installation detected (missing modules)."
    exit()


def banner():
    print " "
    print " #######################################################################"
    print " #                                                                     #"
    print " #  \______   \    |   \______   \______   \ \__    ___/\_____  \      #"
    print " #   |    |  _/    |   /|       _/|     ___/   |    |    /   |   \     #"
    print " #   |    |   \    |  / |    |   \|    |       |    |   /    |    \    #"
    print " #   |______  /______/  |____|_  /|____|       |____|   \_______  /    #"
    print " #          \/                 \/                               \/     #"
    print " #    _________________  .____       _____      _____ __________       #"
    print " #   /   _____/\_____  \ |    |     /     \    /  _  \\\______   \      #"
    print " #   \_____  \  /  / \  \|    |    /  \ /  \  /  /_\  \|     ___/      #"
    print " #   /        \/   \_/.  \    |___/    Y    \/    |    \    |          #"
    print " #  /_______  /\_____\ \_/_______ \____|__  /\____|__  /____|          #"
    print " #          \/        \__>       \/       \/         \/                #"
    print " #                                                                     #"
    print " #    Created By: Milad Khoshdel      Blog: https://blog.regux.com     #"
    print " #                                    E-Mail: miladkhoshdel@gmail.com  #"
    print " #######################################################################"
    print " "


def usage():
    print" "
    print"  Usage: ./burp-to-sqlmap.py [options]"
    print"  Options: -f, --file               <BurpSuit State File>"
    print"  Options: -o, --outputdirectory    <Output Directory>"
    print"  Options: -s, --sqlmappath         <SQLMap Path>"
    print"  Options: -p, --proxy              <Use Proxy>"
    print"  Example: python burp-to-sqlmap.py -f [BURP-STATE-FILE] -o [OUTPUT-DIRECTORY] -s [SQLMap-Path] -p [Proxy]"
    print" "

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file")
    parser.add_argument("-o", "--outputdirectory")
    parser.add_argument("-s", "--sqlmappath")
    parser.add_argument("-p", "--proxy")
    args = parser.parse_args()

    if not args.file or not args.outputdirectory or not args.sqlmappath:
        banner()
        usage()
        sys.exit(0)

    if args.proxy:
        proxyvalue = "--proxy " + args.proxy
    else:
        proxyvalue = ""


    vulnerablefiles = []
    banner()
    filename = args.file
    directory = args.outputdirectory
    sqlmappath = args.sqlmappath
    if not os.path.exists(directory):
        os.makedirs(directory)

    if sys.platform.startswith("win32"):
        runWindows(filename, directory, sqlmappath, proxyvalue, vulnerablefiles)
    elif sys.platform.startswith("linux"):
        runLinux(filename, directory, sqlmappath, proxyvalue, vulnerablefiles)
#        print "Args:\nfile=" + args.file + ";outputdirectory="+args.outputdirectory + ";sqlmappath="+args.sqlmappath
    else:
        print "[+] Error: Unsupported OS Detected!"

def runWindows(filename, directory, sqlmappath, proxyvalue, vulnerablefiles):
    packetnumber = 0
    print " [+] Exporting Packets ..."
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print "   [-] Packet " + str(packetnumber) + " Exported."
            outfile = open(os.path.join(args.outputdirectory, str(packetnumber) + ".txt"), "w")
            outfile.write(i.text.strip())
        print " "
        print str(packetnumber) + " Packets Exported Successfully."
        print " "

    print " [+] Testing SQL Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)"
    for file in os.listdir(directory):
        print "   [-] Performing SQL Injection on packet number " + file[:-4] + ". Please Wait ..."
        os.system("python " + sqlmappath + "\sqlmap.py -r " + os.path.dirname(os.path.realpath(
            __file__)) + "\\" + directory + "\\" + file + " --batch " + proxyvalue + " > " + os.path.dirname(
            os.path.realpath(__file__)) + "\\" + directory + "\\testresult" + file)
        if 'is vulnerable' in open(directory + "\\testresult" + file).read() or "Payload:" in open(
                directory + "\\testresult" + file).read():
            print "    - URL is Vulnerable."
            vulnerablefiles.append(file)
        else:
            print "    - URL is not Vulnerable."
        print "    - Output saved in " + directory + "\\testresult" + file
    print " "
    print "--------------"
    print "Test Done."
    print "Result:"
    if not vulnerablefiles:
        print "No vulnerabilities found on your target."
    else:
        for items in vulnerablefiles:
            print "Packet " + items[:-4] + " is vulnerable to SQL Injection. for more information please see " + items
    print "--------------"
    print " "

def runLinux(filename, directory, sqlmappath, proxyvalue, vulnerablefiles):
    packetnumber = 0
    print " [+] Exporting Packets ..."
    with open(filename, 'r') as f:
        soup = BeautifulSoup(f.read(), "html.parser")
        for i in soup.find_all("request"):
            packetnumber = packetnumber + 1
            print "   [-] Packet " + str(packetnumber) + " Exported."
            outfile = codecs.open(os.path.join(directory, str(packetnumber) + ".txt"), "w", "utf-16le")
            outfile.write(''.join(i.text.strip().split("\x00")))
        print " "
        print str(packetnumber) + " Packets Exported Successfully."
        print " "

    print " [+] Testing SQL Injection on packets ...  (Based on your network connection Test can take up to 5 minutes.)"
    for file in os.listdir(directory):
        allParams = getParamsFromRequest(os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file)
        for param in allParams:
            if param == "SKIP_REQUEST":
                print "[+] Skipping request file: %s! The parameters could not be identified!" % (file)
                break
            print "   [-] Performing SQL Injection on packet number " + file[:-4] + " Parameter: " + param +". Please Wait ..."
            cmd = "python " + sqlmappath + "/sqlmap.py -r " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/" + file + " -p " + str(param) + " --batch " + proxyvalue + " > " + os.path.dirname(os.path.realpath(__file__)) + "/" + directory + "/testresult_" + param + "_" + file
            cmd = ''.join(cmd.split('\x00'))
            print "[-] Command used: %s" % (cmd)
            os.system(cmd)
            if 'is vulnerable' in open(directory + "/testresult_" + ''.join(param.split('\00')) + "_" + file).read() or "Payload:" in open(
                    directory + "/testresult_" + ''.join(param.split('\00')) + "_" + file).read():
                print "    - URL is Vulnerable."
                vulnerablefiles.append(file)
            else:
                print "    - URL is not Vulnerable."
            print "    - Output saved in " + directory + "/testresult" + file
            print " "
            print "--------------"
            print "Test Done."
            print "Result:"
            if not vulnerablefiles:
                print "No vulnerabilities found on your target."
            else:
                for items in vulnerablefiles:
                     print "Packet " + items[:-4] + " is vulnerable to SQL Injection. for more information please see " + items
            print "--------------"
            print " "

def getParamsFromRequest(file):
    f = open(file, "r")
    returnParams = []
    bPostParamsOnNextLine = 0
    bSkipRequest = 0
    lineCount = 0
    bIsPost = 0
    for line in f:
        line = ''.join(line.split('\00'))
        lineCount = lineCount +1
        arr = line.split(" ")
        if ''.join(arr[0].split('\00')) == "GET":
            print "[+] GET request found in file %s: %s" %(file, line)
            strParams = arr[1].split("?")[1]
            arrSepParams = strParams.split("&")
            for item in arrSepParams:
                returnParams.append(item.split("=")[0])
            break
        elif ''.join(arr[0].split('\00')) == "POST":
            print "[+] POST request found in file %s: %s" %(file, line)
            bIsPost = 1
        elif len(arr[0])<5 and bIsPost == 1:
            bPostParamsOnNextLine = 1
        elif arr[0] ==  "Content-Type:" and arr[1].strip() != "application/x-www-form-urlencoded":
            bSkipRequest = 1
            returnParams[:] = []
            returnParams.append("SKIP_REQUEST")
            break
        elif bIsPost == 1 and bPostParamsOnNextLine == 1:
            if bPostParamsOnNextLine == 1:
                 arrSepParams = line.split("&")
                 for item in arrSepParams:
                     returnParams.append(item.split("=")[0])
                 break
    return returnParams


if __name__ == "__main__":
    main()