#!/bin/bash

################################################################################
#                                                                              #
#                             S U B T R A C K E R                              #
#                                                                              #
#   Identify hidden subdomains with Subtracker [Author: Your Name]             #
#                                                                              #
#                           [Author: ReverseTEN]                               #
#                                                                              #
#              GitHub: https://github.com/ReverseTEN/subtracker                #
#                                                                              #
################################################################################




check_requirements() {
  # List of required packages and their installation commands
  declare -A packages=(
    ["subfinder"]="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["anew"]="go install -v github.com/tomnomnom/anew@latest"
    ["dnsgen"]="git clone https://github.com/ProjectAnte/dnsgen.git"
    ["shuffledns"]="go install -v github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
  )

  # Check if required packages are installed
  for package in "${!packages[@]}"; do
    if ! command -v "${package}" >/dev/null 2>&1; then
      echo "[inf] The package '${package}' is required but not installed. Install it with: ${packages[$package]}"
      exit 1
    fi
  done

# Check if the dependency file exists and is readable
  if [ -f "dependency/dependency.zip" ] && [ -r "dependency/dependency.zip" ]; then
  # Save the current working directory to a stack
    pushd .
  # Extract the dependency.zip file to the current directory
    cd dependency && unzip -jo dependency.zip >/dev/null
    # Restore the original working directory
    popd
  else
    echo "[err] The dependency folder does not have the required file dependency.zip"
    echo "      Download the file from https://github.com/exmple/example and place it in the dependency folder"
    exit 1
  fi

# Check if resolvers.txt and wordlist.txt files exist in dependency folder
  if [ ! -f "dependency/resolvers.txt" ] || [ ! -f "dependency/wordlist.txt" ]; then
    echo "[err] The dependency folder does not have the required files resolvers.txt and/or wordlist.txt"
    echo "      Please make sure that the files are present in the dependency folder"
    exit 1
  fi
}



first_run() {



    mkdir -p .tmp
    mkdir $1
    # Find subdomains using crt.sh
    echo "[+] Running crt.sh"
    curl -s https://crt.sh/\?q\=\%25.${1}\&output\=json | jq . | grep 'name_value' | awk '{print $2}' | sed -e 's/"//g'| sed -e 's/,//g' |  awk '{gsub(/\\n/,"\n")}1' | sort -u > .tmp/crt-${1}

    
    # Find subdomains using subfinder

    echo "[+] Runing Subfinder"
    subfinder -d ${1} -silent sort -u > .tmp/subfinder-${1}
    

    # Use curl to query crt.sh for new subdomains related to the target domain,
    # and use jq and sed to extract and format the domain names.
    # Then save the results to a file in the temporary directory.
    echo "[+] Runing abuseipdb"
    curl -s https://www.abuseipdb.com/whois/${1} -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/.'${1}'/' | sort -u > .tmp/abuseipdb-${1}
    
    
    echo "[+] Merging and remove Duplicate"
    #sorts and merges three different files containing subdomains discovered through various methods, then saves the result to a text file with the target name.
    sort .tmp/abuseipdb-${1} .tmp/crt-${1} .tmp/subfinder-${1} | uniq > $1/${1}-subdomains.txt
    rm -rf .tmp
    
    #line displays the number of subdomains found for the target and passes it to the next function for further processing.
    echo "[*] Target :$1 -> $(cat $1/${1}-subdomains.txt  | wc -l) Subdomain found" 
    dns_ $1
    
    echo "[*] Target :$1 -> $(cat $1/$1-dns | wc -l) Dns From Stage 1"
    echo "[*] Target :$1 -> $(cat $1/$1-lastdns | wc -l) Dns From Last Stage !"
    
    #updated subdomains
    cat $1/$1-lastdns | anew $1/$1-subdomains.txt > $1/$1-valuable_subdomains.txt
    
    #checks whether there are any valuable subdomains found from the DNS brute force and notifies the user accordingly.
    if [ -s "$1/$1-valuable_subdomains.txt" ]; then
        echo "[:globe_with_meridians:] Valuable subdomain with high potential from DNS Brute force: " | notify -silent
        cat $1/$1-valuable_subdomains.txt | notify -silent
    else
        :
    fi
    
    echo "[*] -> $(cat $1/$1-valuable_subdomains.txt | wc -l) High-Potential Target Found!"  

    # number of updated subdomains for the target.
    echo "[*] Update  $1 Subdomains To -> $(cat $1/${1}-subdomains.txt  | wc -l)"
    
    rm -rf $1/$1-dns
    rm -rf $1/$1-fulldns
    rm -rf $1/$1-lastdns
    


}


check_for_new_subdomains() {

    # This function checks and detects new subdomains, and updates the main subdomain list
    # which was obtained in the first_run function.
    echo "Start Check For New Subdomains "
    mkdir -p $1/.tmp
    
    echo "[+] Running crt.sh for new sub"
    curl -s https://crt.sh/\?q\=\%25.${1}\&output\=json | jq . | grep 'name_value' | awk '{print $2}' | sed -e 's/"//g'| sed -e 's/,//g' |  awk '{gsub(/\\n/,"\n")}1' | sort -u > $1/.tmp/crt-${1}
    
    echo "[+] Runing Subfinder for new sub"
    subfinder -d ${1} -silent sort -u > $1/.tmp/subfinder-${1}
    
    # Use curl to query crt.sh for new subdomains related to the target domain,
    # and use jq and sed to extract and format the domain names.
    # Then save the results to a file in the temporary directory.
    echo "[+] Runing abuseipdb for new sub"
    curl -s https://www.abuseipdb.com/whois/${1} -H "user-agent: Chrome" | grep -E '<li>\w.*</li>' | sed -E 's/<\/?li>//g' | sed -e 's/$/.'${1}'/' | sort -u > $1/.tmp/abuseipdb-${1}
    
    echo "[+] Merging and remove Duplicate for new sub"
    
    sort $1/.tmp/abuseipdb-${1} $1/.tmp/crt-${1} $1/.tmp/subfinder-${1} | uniq > $1/${1}-Newsubdomains.txt
    rm -rf $1/.tmp
    
    echo "[*] Target :$1 -> $(cat $1/${1}-Newsubdomains.txt  | wc -l) NewSubdomain found" 
    echo "[*] Starting the initial stage of Dnsgen" 
    
    cat $1/$1-Newsubdomains.txt | dnsgen - > $1/$1-dnsgen2

    # Use shuffledns to resolve the DNS records generated by dnsgen,
    # using a list of resolvers and a wordlist to generate permutations of domain names,
    # and save the results to a file.
    shuffledns -silent -d $1 -w dependency/wordlist.txt -r dependency/resolvers.txt -o $1/$1-dns2
    
    # Combine the original list of new subdomains with the list generated by dnsgen,
    # remove duplicates, and save the results to a file.
    cat $1/$1-Newsubdomains.txt > $1/$1-subgen2
    sort $1/$1-subgen2 $1/$1-dnsgen2 | uniq > $1/${1}-fulldns2
    
    rm -rf $1/$1-dnsgen2
    rm -rf $1/$1-subgen2

    # Use shuffledns to resolve the DNS names and save the results in a file
    echo "[*] Shuffle DNS for new subdomains." 
    shuffledns -silent -d $1 -list $1/${1}-fulldns2 -r dependency/resolvers.txt -o $1/$1-lastdns2

    echo "[*] Target :$1 -> $(cat $1/$1-dns2 | wc -l) Dns From Stage 1" 
    echo "[*] Target :$1 -> $(cat $1/$1-lastdns2 | wc -l) Dns From Last Stage !" 

    cat $1/$1-lastdns2 | anew $1/$1-Newsubdomains.txt > $1/$1-valuable_subdomains2.txt
        
        
    #checks whether there are any valuable subdomains found from the DNS brute force and notifies the user accordingly.
    if [ -s "$1/$1-valuable_subdomains2.txt" ]; then
        echo "[:globe_with_meridians:] Valuable subdomain with high potential from DNS Brute force: " | notify -silent
        cat $1/$1-valuable_subdomains2.txt | notify -silent
    else
        :
    fi

    #updated main subdomains 
    cat $1/$1-Newsubdomains.txt | anew $1/$1-subdomains.txt > $1/$1-NewTarget.txt

    if [ -s "$1/$1-NewTarget.txt" ]; then
        echo "[:globe_with_meridians:] Recently added subdomain: " | notify -silent
        cat $1/$1-NewTarget.txt | notify -silent
    else
        echo "[:globe_with_meridians:] No new subdomains have been discovered. " | notify -silent
    fi

    echo "[*] -> $(cat $1/$1-valuable_subdomains2.txt | wc -l) High-Potential Target Found!" 
    echo "[*] -> $(cat $1/$1-NewTarget.txt | wc -l) NewSubdomain Found!" 
    echo "[*] Update  $1 Subdomains To -> $(cat $1/${1}-Newsubdomains.txt  | wc -l)" 
    
    rm -rf $1/$1-dns2
    rm -rf $1/$1-fulldns2
    rm -rf $1/$1-lastdns2
    rm -rf $1/$1-Newsubdomains.txt
    rm -rf $1/$1-NewTarget.txt
    

}



dns_ (){
    #Resolve subdomains with shuffledns using a wordlist and resolvers
    echo "[*] Resolving Subdomains: This May Take a Moment to Complete."
    shuffledns -silent -d $1 -w dependency/wordlist.txt -silent -r dependency/resolvers.txt -o $1/$1-dns
    echo "[*] Stage 1 Dnsgen Start!" 
    
    # Generate additional subdomains using dnsgen and combine with original list
    cat $1/$1-subdomains.txt | dnsgen - > $1/$1-dnsgen
    cat $1/$1-subdomains.txt > $1/$1-subgen
    sort $1/$1-subgen $1/$1-dnsgen | uniq > $1/${1}-fulldns
    rm -rf $1/$1-dnsgen
    rm -rf $1/$1-subgen
    echo "[*] Start Shuffle dns From Stage 1" 

    # Resolve subdomains again using shuffledns with newly generated list
    shuffledns -silent -d $1 -list $1/${1}-fulldns -r dependency/resolvers.txt -o $1/$1-lastdns
    
}


A_record_check (){
    echo "[*] Verifying A_Records"
    local str="$(host -t A "notfoundsnssssas.$1")"
    if echo "$str" | grep "not found:" >/dev/null ; then
        echo "[*] Let's identify more subdomains."
        first_run $1
    else 
        echo "[!] The A_record are responding to all requests"
    fi
}

Subdomain_Watcher(){

    check_requirements
    # if the directory exists
    if [ -d "$1" ]; then
        # call check_for_new_subdomains function with the argument
        check_for_new_subdomains $1
    else
        # call A_record_check function with the argument
        A_record_check $1
    fi
}



Subdomain_Watcher $1