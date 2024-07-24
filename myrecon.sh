#!/bin/bash

#colors
red='\e[1;31m%s\e[0m\n'
yellow='\e[1;33m%s\e[0m\n'
white='\e[1;37m%s\e[0m\n'
blue='\e[0;34m%s\e[0m\n'

#enter domain name and company name
echo ""
read -p $'\e[31menter domain name\e[0m : ' domain
read -p $'\e[31menter a company name\e[0m : '  cname
read -p $'\e[31menter your github token\e[0m : ' GT
read -p $'\e[31mDo you want to crawl urls[Y|N]\e[0m : ' crawls

#assign a dir
dir=~/bugbounty/${cname}
sub=$dir/subdomain_enum
httpx=$dir/httpx
crawl=$dir/crawling_urls
gf=$dir/gf_list
port=$dir/port_scan

#create a directory
mkdir -p ${dir}
mkdir ${sub}
mkdir ${httpx}

#subdomain enumeration
cd ${sub}

echo -e "\n"
printf "$white" "assetfinder.."
echo ""
sleep 5
assetfinder -subs-only ${domain} | tee assetfinder.txt
echo -e "\n"

echo -e "\n"
printf "$white" "subfinder.."
echo ""
sleep 5
subfinder -d ${domain} -all -silent -o subfinder.txt
echo -e "\n"

if [[ -n ${GT} ]]
then
#github-subdomains
echo -e "\n"
printf "$white" "github-subdomains.."
echo ""
sleep 5
github-subdomains -d ${domain} -t ${GT} -o githubsub.txt 2>/dev/null
echo -e "\n"
else
#knockpy
echo -e "\n"
printf "$white" "knockpy.."
echo ""
sleep 5
knockpy -d ${domain} --recon --json
echo -e "\n"
cat ${domain}*.json | jq '.[].domain'| sed s/\"//g | tee knockpy.txt 
rm -rf ${domain}*.json
echo -e "\n"
fi

#uniq subdomains
cat assetfinder.txt subfinder.txt githubsub.txt knockpy.txt | sort -u | tee uniqsubdomains.txt
cat uniqsubdomains.txt | wc -l

#cat uniqsubdomains.txt | notify -silent -bulk

#subdomain takeover
echo -e "\n"
printf "$white" "subjack.."
echo ""
sleep 5
subjack -w uniqsubdomains.txt -v | tee subdomaintakeover.txt
cat subdomaintakeover.txt | egrep -v "[Not Vulnerable]" | tee 404vulnerable.txt
# cat 404vulnerable.txt | notify -silent -bulk
rm -rf subdomaintakeover.txt 

#httpx 
cd ..
cd ${httpx}

echo -e "\n"
printf "$white" "httpx.."
echo ""
sleep 5
httpx -l ${sub}/uniqsubdomains.txt  -sc -title -td -fr -ip -asn -silent -o httpx.txt
echo -e "\n"

#cat httpx.txt | notify -silent -bulk

#status code(200,403,404) text and ip
cat httpx.txt | awk '{print $1}'> httpxAll.txt
cat httpx.txt | grep "200" | awk '{print $1}'> httpx200.txt
cat httpx.txt | grep "403" | awk '{print $1}'> httpx403.txt
cat httpx.txt | grep "404" | awk '{print $1}'> httpx404.txt
cat httpx.txt | grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" > ip.txt


#craweling
cd ..

case ${crawls} in
    'y' | 'Y' | 'yes' | 'YES')
mkdir ${crawl}
cd ${crawl}
echo -e "\n"
printf "$white" "crawl[katana,gau,waybackurls,gospider].."
echo ""
while read url
do
   sleep 3
   katana -u ${url} -d 4 -jc -silent -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg | anew katana.txt 
   #waymore -i ${url} -mode U | tee waymore.txt
   #gau ${url} | tee gau.txt
   #gospider -s ${url} -c 100 -d 8 -o gospider.txt
   #waybackurls ${url} | tee waybackurls.txt 
done <  ${httpx}/httpx200.txt
echo -e "\n"

#juicy endpoints

#js
cat katana.txt | grep -Ei "\.js$" | sort -u | httpx -silent -mc 200  | tee katana_js.txt
echo -e "\n"

#pdf
cat katana.txt | grep -Ei "\.pdf$" | sort -u | httpx -silent -mc 200  | tee katana_pdf.txt
echo -e "\n"

#docs and doc
cat katana.txt | grep -Ei "\.doc$|\.docs$" | sort -u | httpx -silent -mc 200  | tee  katana_doc.txt
echo -e "\n"

#xls
cat katana.txt | grep -Ei "\.xls$" | sort -u | httpx -silent -mc 200  | tee katana_xls.txt
echo -e "\n"

#common
cat katana.txt | grep -Ei ".txt|.log|.cache|.secret|.db|.backup|.yml|.json|.gz|.rar|.zip|.config|.asp|.php|.py|.action|.jsp" | httpx -silent -mc 200 | tee katana_common.txt
echo -e "\n"

#gf patterns
cd ..

mkdir $gf
cd ${gf} 

#gf pattern using find [xss,sqli,redirect,lfi] parameters
cat $crawl/katana.txt | gf allparam | uro > gf_Allparam.txt
cat $crawl/katana.txt | gf xss | uro > gf_xss.txt
cat $crawl/katana.txt | gf sqli | uro > gf_sqli.txt
cat $crawl/katana.txt | gf redirect | uro > gf_redirect.txt
cat $crawl/katana.txt | gf lfi | uro > gf_lfi.txt
;;
*)
 printf "${red}" "skip craweling urls"
;;
esac

#port scanning

#comment
: '
cd ..
mkdir ${port}
cd ${port}
cat uniqsubdomains.txt | dnsx -a -ro | sort -u | tee ip.txt
echo -e "\n"
sleep 5
naabu -list ip.txt -silent -top-ports 1000 -exclude-ports 21,22,25,80,443 -o naabu.txt
'


