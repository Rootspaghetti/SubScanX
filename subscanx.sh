#!/bin/bash

# Renkleri tanımlıyoruz
COLORS=("31" "32" "33" "34" "35" "36" "91" "92" "93" "94" "95" "96")

# Rastgele bir renk seçiyoruz
RANDOM_COLOR=${COLORS[$RANDOM % ${#COLORS[@]}]}

# SubScanX ana başlık
echo -e "\033[${RANDOM_COLOR}m"
figlet "SubScanX" | lolcat

# Alt başlık
echo -e "\033[1;37mby: \033[1;33mRoot@Spaghetti\033[0m"

# Get domain name from user input
read -p "Enter the domain name: " domain

# Create a directory with the domain name
output_dir="${domain}_results"
mkdir -p "${output_dir}"

echo -e "\033[1;32mResults will be saved in the directory: ${output_dir}\033[0m"

echo -e "\033[1;32mStarting subdomain discovery for ${domain}...\033[0m"
subfinder -d ${domain} -o ${output_dir}/subdomains.txt
echo -e "\033[1;32mSubdomains saved to ${output_dir}/subdomains.txt.\033[0m"

echo -e "\033[1;32mRunning HTTPX scans...\033[0m"
httpx -l ${output_dir}/subdomains.txt -sc -location -o ${output_dir}/httpxwithsc.txt
echo -e "\033[1;32mHTTPX with status codes saved to ${output_dir}/httpxwithsc.txt.\033[0m"

httpx -l ${output_dir}/subdomains.txt -o ${output_dir}/httpxwithoutsc.txt
echo -e "\033[1;32mHTTPX results without status codes saved to ${output_dir}/httpxswithoutsc.txt.\033[0m"

httpx -l ${output_dir}/subdomains.txt -fc 200,201,202,203,204,205,206,207,208,226,300,301,302,303,304,305,306,307,308,500,501,502,503,504,505,506,507,508,510,511,400 -o ${output_dir}/httpx403401.txt
echo -e "\033[1;32mHTTPX results for filtered status codes saved to ${output_dir}/httpx403401.txt.\033[0m"

echo -e "\033[1;32mRunning Social Hunter scan...\033[0m"
socialhunter -f ${output_dir}/httpxswithoutsc.txt | tee ${output_dir}/socialhijacking.txt
echo -e "\033[1;32mSocial hijacking results saved to ${output_dir}/socialhijacking.txt.\033[0m"

echo -e "\033[1;32mScanning for CORS vulnerabilities...\033[0m"
python3 tools/Corsy/corsy.py -i ${output_dir}/httpxswithoutsc.txt -o ${output_dir}/cors.txt
echo -e "\033[1;32mCORS scan results saved to ${output_dir}/cors.txt.\033[0m"

echo -e "\033[1;32mRunning Nuclei Fuzzer...\033[0m"
nf -d ${domain} | tee ${output_dir}/nucleifuzzer.txt
echo -e "\033[1;32mNuclei Fuzzer results saved to ${output_dir}/nucleifuzzer.txt.\033[0m"

echo -e "\033[1;32mAttempting 403 bypass...\033[0m"
bash tools/4-ZERO-3/403-bypass.sh -u ${output_dir}/httpx403401.txt --exploit | tee ${output_dir}/403bypass.txt
echo -e "\033[1;32m403 bypass results saved to ${output_dir}/403bypass.txt.\033[0m"

echo -e "\033[1;32mRunning directory brute-forcing with Feroxbuster...\033[0m"
feroxbuster -u ${domain} -w directory-list-2.3-medium.txt -A -o ${output_dir}/feroxbuster.txt
echo -e "\033[1;32mFeroxbuster results saved to ${output_dir}/feroxbuster.txt.\033[0m"

echo -e "\033[1;32mRunning Nmap vulnerability scan...\033[0m"
nmap --script vuln -oN ${output_dir}/nmapvuln.txt ${domain}
echo -e "\033[1;32mNmap results saved to ${output_dir}/nmapvuln.txt.\033[0m"

echo -e "\033[1;32mRunning Subzy for vulnerable subdomain detection...\033[0m"
subzy run --targets ${output_dir}/httpxswithoutsc.txt --vuln
echo -e "\033[1;32mSubzy results displayed above.\033[0m"

echo -e "\033[1;32mRunning Arjun for parameter discovery...\033[0m"
arjun -i ${output_dir}/httpxswithoutsc.txt -oT ${output_dir}/arjunsubdomains.txt
echo -e "\033[1;32mArjun results saved to ${output_dir}/arjunsubdomains.txt.\033[0m"

echo -e "\033[1;32mGathering historical URLs with gau and waybackurls...\033[0m"
echo ${domain} | gau | tee ${output_dir}/urlsgau.txt
waybackurls https:${domain} | tee ${output_dir}/waybackurls.txt
echo -e "\033[1;32mHistorical URLs saved to ${output_dir}/urlsgau.txt and ${output_dir}/waybackurls.txt.\033[0m"

echo -e "\033[1;32mCombining and filtering URLs...\033[0m"
cat ${output_dir}/waybackurls.txt ${output_dir}/urlsgau.txt | sort | uniq > ${output_dir}/urls.txt
echo -e "\033[1;32mAll unique URLs saved to ${output_dir}/urls.txt.\033[0m"

echo -e "\033[1;32mFiltering URLs by file type...\033[0m"
cat ${output_dir}/urls.txt | grep "js" | tee ${output_dir}/js.txt
cat ${output_dir}/urls.txt | grep "png" | tee ${output_dir}/domainpng.txt
cat ${output_dir}/urls.txt | grep "jpg" | tee ${output_dir}/domainjpg.txt
cat ${output_dir}/urls.txt | grep "pdf" | tee ${output_dir}/domainpdf.txt
cat ${output_dir}/urls.txt | grep "doc" | tee ${output_dir}/domaindocs.txt
cat ${output_dir}/urls.txt | grep "sql" | tee ${output_dir}/domainsql.txt
cat ${output_dir}/urls.txt | grep "json" | tee ${output_dir}/domainjson.txt
cat ${output_dir}/urls.txt | grep "admin" | tee ${output_dir}/domainadmin.txt
cat ${output_dir}/urls.txt | grep "api" | tee ${output_dir}/domainapi.txt
cat ${output_dir}/urls.txt | grep "config" | tee ${output_dir}/domainconfig.txt
cat ${output_dir}/urls.txt | grep "backup" | tee ${output_dir}/domainbackup.txt
echo -e "\033[1;32mURLs filtered by type and saved in ${output_dir}.\033[0m"

echo -e "\033[1;32mExtracting vulnerabilities with GF patterns...\033[0m"
cat ${output_dir}/urls.txt | uro | gf sqli | sed 's/=.*/=/' | tee ${output_dir}/sqli.txt
cat ${output_dir}/urls.txt | uro | gf xss  | sed 's/=.*/=/' | tee ${output_dir}/xss.txt
cat ${output_dir}/urls.txt | uro | gf ssrf | sed 's/=.*/=/' | tee ${output_dir}/ssrf.txt
cat ${output_dir}/urls.txt | uro | gf redirect| sed 's/=.*/=/' | tee ${output_dir}/redirect.txt
cat ${output_dir}/urls.txt | uro | gf lfi | sed 's/=.*/=/' | tee ${output_dir}/lfi.txt
cat ${output_dir}/urls.txt | uro | gf idor | sed 's/=.*/=/' | tee ${output_dir}/idor.txt
echo -e "\033[1;32mGF pattern results saved to ${output_dir}.\033[0m"

echo -e "\033[1;32mRunning Nuclei scans for vulnerabilities...\033[0m"
nuclei -l ${output_dir}/lfi.txt -tags "lfi"
nuclei -l ${output_dir}/redirect.txt -tags "open-redirect"
nuclei -l ${output_dir}/ssrf.txt -tags "ssrf"
nuclei -l ${output_dir}/idor.txt -tags "idor"
nuclei -l ${output_dir}/xss.txt -tags "xss"
nuclei -l ${output_dir}/sqli.txt -tags "sql"
echo -e "\033[1;32mNuclei scans completed.\033[0m"

echo -e "\033[1;32mTesting SQL injection with SQLMap...\033[0m"
sqlmap -m ${output_dir}/sqli.txt --batch --level=5 --risk=3 --dbs
echo -e "\033[1;32mSQLMap testing completed.\033[0m"

echo -e "\033[1;32mRunning Dalfox for XSS vulnerability detection...\033[0m"
cat ${output_dir}/xss.txt | sed 's/=.*/=/' | dalfox pipe
echo -e "\033[1;32mDalfox scan completed.\033[0m"
echo -e "\033[1;31mHave a good Hunting :-)\033[0m"
