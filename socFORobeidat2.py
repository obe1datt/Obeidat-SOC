import requests
import json 
from bs4 import BeautifulSoup
def ip_info(ip_add):
        ip = ip_add
        base_url = f'https://ipinfo.io/{ip}/json'

        req = requests.get(base_url)
        res = req.json()


        for vlaue  in res:
            print(vlaue, ':' , res[vlaue])



def ip_info_token(ip_addr):
        ip = ip_addr
        token = 'dd14d85d9daeec'
        base_url =   f'https://ipinfo.io/{ip}?token={token}'

        req = requests.get(base_url)
        res = req.json()


        for vlaue  in res:
            print(vlaue, ':' , res[vlaue])


def search_for_ip():
    print("IP searching has been started ....\n")
    threat_fox_apikey ={
     "API-KEY": "62a103d7b76150796e9b6e669acbc04e",
    }
    data_to_post  = { "query": "search_ioc", 
                     "search_term": "139.180.203.104" }
    
    json_data = json.dumps(data_to_post)
    base_url = "https://threatfox-api.abuse.ch/api/v1/"
    
    req = requests.post(base_url , data=json_data  ,headers=threat_fox_apikey)
    res = req.json()
    

    for val in res.get('data'):
          for k in val:
                print( k ,":" ,  val[k])


def VT_IP(ip):
    VTotal_Key = {'x-apikey':'568991ceebba95d9b80fa01b234762d9a4965d352b8cb3be795fe9a80cda661c'}

    ip = ip
    base_url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"


    req = requests.get(url=base_url , headers=VTotal_Key)
    res =  req.json()
    alldata  = res.get('data').get('attributes')

    for key in alldata :
        if key == 'as_owner':
              print("ASN owner:" , alldata['as_owner'])
        if key == 'asn' :
            print('Autonomous System Numbers: ',alldata['asn'])
        if key == 'country' :
            print('Country : ' , alldata['country'])
        #if key  == 'whois':
        #    print('############################# WHO IS #############################')
        #    print('Who is Inof: ')
        #    print(alldata['whois'])
        if  key == 'last_analysis_stats':
            print('Network Rnage : ',alldata['network'])
        if key == 'last_analysis_results':
            print('############################# Engine SCAN  #############################')
            for  k in  alldata['last_analysis_results']:
                if alldata['last_analysis_results'][k].get('category') == 'malicious' :
                    print("Engine Name" , alldata['last_analysis_results'][k].get('engine_name'))
                    print("\tMalware Catagoty" , alldata['last_analysis_results'][k].get('category"'))
                    print("\tIP Result" , alldata['last_analysis_results'][k].get('result'))
                    print("\tMethod" , alldata['last_analysis_results'][k].get('method'))
        if key == 'continent':
            print('continent',alldata['continent'])
        if key == 'reputation' :
            print('IP Reputation ',alldata['reputation'])








url   = 'https://feodotracker.abuse.ch/browse.php?search=105.184.115.128'

req =  requests.get(url)
soup = BeautifulSoup(req.content, "html.parser")


s  = soup.find("table", class_="table table-sm table-hover table-bordered")
lines2 = s.find_all('td')
for l in lines2:
     print(l.text.lstrip())    


"""
VT_IP('105.184.115.128')
print('#' * 40)
search_for_ip()    
print('#' * 40)
ip_info_token('105.184.115.128')
"""



#ip_info('128.140.35.86')
#print("#################")
#ip_info_token('128.140.35.86')
