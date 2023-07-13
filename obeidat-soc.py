import requests
import json
import argparse
import sys 
from bs4 import BeautifulSoup 
global threat_fox_apikey 

threat_fox_apikey ={
     "API-KEY": "62a103d7b76150796e9b6e669acbc04e",
    }

global malware_bazar_apikey 
malware_bazar_apikey = {
    'API-KEY': '8eaf79f47c5790979b9950bed5c7f03b',
    }

global virus_total_apikey 
virus_total_apikey = VTotal_Key = {

    'x-apikey':'568991ceebba95d9b80fa01b234762d9a4965d352b8cb3be795fe9a80cda661c'
    }

global metadefender_api_key 
metadefender_api_key = {
        'apikey': "b4372a2b95e8f0899cf0e3aefb83e9c2"
    }



def search_for_hash(hash):
    print("Hash searching has been started ....\n")
    

    data_to_post ={
       "query": "search_hash", "hash": hash
    }

    json_data = json.dumps(data_to_post)
    base_url = "https://threatfox-api.abuse.ch/api/v1/"
    try:
        req = requests.post(base_url , data=json_data  ,headers=threat_fox_apikey)
        res = req.json()
        for data in res['data']:
   
            print('Malware :', data['malware'])
            print('Maleare Name:',data['malware_printable'])
            print('Maleare Alies:',data['malware_alias'])
            print('Maleare pedia', data['malware_malpedia'])
            print('First Seen:', data['first_seen'])
            print('Last Seen:', data['last_seen'])
            print('IP of malware :', data['ioc'])
            print('Threat Type :', data['threat_type'])
            print('Threat Type Description:', data['threat_type_desc'])
            print('IOC Type:', data['ioc_type'])
            print('IOC Type Description:', data['ioc_type_desc'])
            print('refrence', data['reference'])
            print('------------------------------------------------------------')

    except:
        
        print("No Result Found ")


def search_for_hash_bz(hash_value):
    print("Hash searching has been started ....\n")
    headers = malware_bazar_apikey

    data_to_post ={
           "query": "get_info", "hash": hash_value
             }


    base_url = "https://mb-api.abuse.ch/api/v1/"
    try:
        req = requests.post(url=base_url , data=data_to_post ,headers=headers)
        res = req.json()
        for data in res['data']:
            
             print("Malware File name:",data['file_name'])
             print("Malware Size File:",data['file_size'])
             print("Malware File Type:",data['file_type'])
             print("Malware Family :",data['signature'])
             print("Malware Mime Type:",data['file_type_mime'])
             print("Malware Informatiom:",data['file_information'])
             print("SHA256 Value:",data['sha256_hash'])
             print("SHA2384 Value:",data['sha3_384_hash'])
             print("SHA1 Value:",data['sha1_hash'])
             print("MD5 Value:",data['md5_hash'])
             print("Malware first Seen:",data['first_seen'])
             print("Malware Last Seen :",data['last_seen'])
             print("Delivey Methods :",data['delivery_method'])
             print("Origin County :",data['origin_country'])
             print('-'*40)
    except:
          print("No Result Found ")

def vt_engines(hash_en_value):
    
    VTotal_Key = virus_total_apikey
    id = hash_en_value
    base_url = f"https://www.virustotal.com/api/v3/files/{id}"
    global res

    try:
       req = requests.get(url=base_url , headers=VTotal_Key)
       res =  req.json()
       alldata  = res.get('data').get('attributes')
       for key in alldata:
        if key == 'type_description':
          print('Type of Malware : ' , alldata['type_description'])
        elif key == 'names' :
            print("Malware Name or Names")
            for name in alldata['names']:
                print('\t',name)
        elif  key == 'creation_date':
            print("Malware creation Date :" , alldata['creation_date'])
        elif key == 'crowdsourced_ids_results':
            print()
            print("IOC")
            print()
            print()
            for  ke  in alldata['crowdsourced_ids_results']:
                if  'alert_context' in ke:
                    for ioc in ke['alert_context']:
                        print('\t','Hostname : ',ioc.get('hostname'),' / Protcol :',ioc.get('protocol'),' / Destination Port :',ioc.get('dest_port'), ' / Destination IP :',ioc.get('dest_ip'),' / url:',ioc.get('url'))
            print()
         
        elif key == 'popular_threat_classification':
            print("Malware Class or  Catagory:")
            print("\t",alldata['popular_threat_classification']['suggested_threat_label'])   

        elif key == "detectiteasy":
            print('File information')
            print('\t' ,  alldata['detectiteasy']['filetype'])
        elif key == 'size':
            print('Malware Size : ',alldata['size'])    
        elif key == 'downloadable':
            print('Downloadble ' , alldata['downloadable'])
        elif key == 'first_submission_date':
            print("First Submission Data" , alldata['first_submission_date'])
        elif key == 'last_analysis_date':
            print('Last Analysis Data' , alldata['last_analysis_date'] )
        elif key == 'last_modification_date':
            print('Last Modification Date' , alldata['last_modification_date'])
       alldata  = res.get('data').get('attributes').get("last_analysis_results")
       print("Virus Total Started")
       for key in alldata:
         print("############################# Engine SCAN  #############################")
         if alldata[key].get('category') == 'malicious':
          print("Engine :" , alldata[key].get('engine_name'))
          print('\t',alldata[key].get('category'))
          print('\t',alldata[key].get('result'))
          print('\t',alldata[key].get('method'))
          print('---------------------------------------------------------------')
         else:
             continue
    except:
         print('Not Result In VirusTotal')


def MT(hash_val):
    url = f"https://api.metadefender.com/v4/hash/{hash_val}"

    

    response = requests.request("GET", url, headers=metadefender_api_key)

    res  = response.json()

    for key in  res:
        try:
            if key == 'malware_type' :
              print('Malware Type :' , res['malware_type'])
            elif key == 'malware_family' :
              print('Malware Family :' , res['malware_family'])
            elif key == 'threat_name' :
              print('File or Threat Name :' , res['threat_name'])     
            elif key == 'file_id' :
              print('File ID :' , res['file_id'])   
            elif key == 'data_id' :
              print('Data ID :' , res['data_id'])     
            elif key == 'file_info':
                for k in res['file_info']:
                    print(k , ':' ,res['file_info'][k] ) 
           
        except:
            print("NO Result Found") 
    print("-"*40) 

def VT_IP(ip):
    VTotal_Key = virus_total_apikey

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
                    print('-'*50)
        if key == 'continent':
            print('continent :',alldata['continent'])
        if key == 'reputation' :
            print('IP Reputation :',alldata['reputation'])

def search_for_ip(ip):
    try:
        print("IP searching has been started ....\n")
        data_to_post  = { "query": "search_ioc", 
                        "search_term": ip }
        
        json_data = json.dumps(data_to_post)
        base_url = "https://threatfox-api.abuse.ch/api/v1/"
        
        req = requests.post(base_url , data=json_data  ,headers=threat_fox_apikey)
        res = req.json()
        

        for val in res.get('data'):
            for k in val:
                    print( k ,":" ,  val[k])
    except:
        print("No Result  in ThreatFox ")    

def feodotracker_ip(ip):
      url   = f'https://feodotracker.abuse.ch/browse.php?search={ip}'

      result = []
      req =  requests.get(url)
      soup = BeautifulSoup(req.content, "html.parser")
      s  = soup.find("table", class_="table table-sm table-hover table-bordered")
      lines2 = s.find_all('td')
      for l in lines2:
         result.append(l.text.lstrip())

      print("Creation Date :", result[0])
      print("Malware IP :" , result[1]) 
      print("Malware Fmaliy :" , result[2])
      print("Malware Status", result[3])
      print("ASn :" ,result[4])
      print("Country :" ,result[5])   


def VT_domina(domain):
    base_url  = f'https://www.virustotal.com/api/v3/domains/{domain}'
     

    try: 
            request =  requests.get(base_url , headers=virus_total_apikey)
            response  =  request.json()
            
            

            alldata = response.get('data').get('attributes')
            for data in  alldata:
                if data  == 'last_dns_records':
                    continue
                elif data == 'last_dns_records':
                    continue
                elif data == 'last_analysis_results':
                    continue
                elif data == 'last_https_certificate':
                    continue
                print(data,": ",alldata[data])
            print()
            print('############################# Engine SCANS  #############################')
            for key  in alldata:
                if key == 'last_analysis_results':
                 for scan  in alldata['last_analysis_results']:
                    print("Engine Name :" , scan )
                    print('\tDomain Category :' ,  alldata['last_analysis_results'][scan].get('category'))
                    print('\tResult :' ,  alldata['last_analysis_results'][scan].get('unrated'))
                    print('\tMethod :' ,  alldata['last_analysis_results'][scan].get('method'))
                    print('-'*50)
    except:
        print("Virus Total Erro") 


def search_for_domain(domain):
    try:
        print("IP searching has been started ....\n")
        data_to_post  = { "query": "search_ioc", 
                        "search_term": domain }
        
        json_data = json.dumps(data_to_post)
        base_url = "https://threatfox-api.abuse.ch/api/v1/"
        
        req = requests.post(base_url , data=json_data  ,headers=threat_fox_apikey)
        res = req.json()
        

        for val in res.get('data'):
            for k in val:
                    print( k ,":" ,  val[k])
    except:
        print("No Result  in ThreatFox ") 

def scan_url(url):

    url = "https://www.virustotal.com/api/v3/urls"

    headers = {
        "accept": "application/json",
        "content-type": "application/x-www-form-urlencoded",
        "x-apikey": virus_total_apikey
    }
    
    data_to_post = {
        "url": url
    }

    response = requests.post(url, headers=headers , data=data_to_post)
    alldata =  response.json()

    id =  alldata.get('data').get('id')
    
    return str(id)

import requests


def url_anlysis(url_to_scan):
        headers = { "accept": "application/json",
                    "x-apikey": virus_total_apikey
                        }

        id = scan_url(url_to_scan)
        url = f"https://www.virustotal.com/api/v3/analyses/{id}"
        try:
            request  =  requests.get(url=url , headers=headers)
            response =  request.json()
            print('############################# URL INFORMATION #############################')
            for info in response.get('meta').get('url_info'):
                print(info,':',response['meta']['url_info'][info])

            alldata =  response.get('data').get('attributes')
            print('Gneral Info:',alldata['stats'])
            print('############################# Engine SCAN  #############################')
            for data in alldata['results']:
                print("Engine Name :" , data )
                print('\tDomain Category :' ,  alldata['results'][data].get('category'))
                print('\tResult :' ,  alldata['results'][data].get('unrated'))
                print('\tMethod :' ,  alldata['results'][data].get('method'))
                print('-'*50)
        except:
             print("VirusTotal Error ")           

def main():
    """
    search_for_hash(sys.argv[1])
    search_for_hash_bz(sys.argv[1])
    vt_engines(sys.argv[1])
    MT(sys.argv[1])
    """
    VT_IP('139.180.203.104')
    search_for_ip('139.180.203.104')
if __name__ == "__main__":
    main()    

                  