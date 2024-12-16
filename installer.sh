sudo apt-get install figlet
sudo apt-get install lolcat
sudo apt-get install sqlmap
sudo apt-get install nmap
apt-get install feroxbuster
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo cp ~/go/bin/subfinder /usr/bin/
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
sudo cp ~/go/bin/httpx /usr/bin/
go install github.com/utkusen/socialhunter@latest
sudo cp ~/go/bin/socialhunter /usr/bin/
pip install arjun --break-system-packages
pip install uro --break-system-packages
go install github.com/hahwul/dalfox/v2@latest
sudo cp ~/go/bin/dalfox /usr/bin/
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/bin/
go install github.com/tomnomnom/waybackurls@latest
sudo cp ~/go/bin/waybackurls /usr/bin/
go install github.com/lc/gau/v2/cmd/gau@latest
sudo cp ~/go/bin/gau /usr/bin/
go install -v github.com/PentestPad/subzy@latest
sudo cp ~/go/bin/subzy /usr/bin/
go install github.com/tomnomnom/gf@latest  
git clone [https://github.com/1ndianl33t/Gf-Patterns
sudo cp ~/go/bin/gf /bin/ 
mkdir .gf  
mv ~/Gf-Patterns/*.json ~/.gf
git clone https://github.com/0xKayala/NucleiFuzzer.git && cd NucleiFuzzer && sudo chmod +x install.sh && ./install.sh && nf -h && cd ..
echo -e "\033[1;31mThe installation has been completed. Have a good Hunting.\033[0m"