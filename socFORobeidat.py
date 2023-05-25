import requests 
import json

def search_for_hash(hash):
    print("Hash searching has been started ....\n")
    threat_fox_apikey ={
     "API-KEY": "62a103d7b76150796e9b6e669acbc04e",
    }

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

################################################################


def search_for_hash_bz(hash_value):
    print("Hash searching has been started ....\n")
    headers = {'API-KEY': '8eaf79f47c5790979b9950bed5c7f03b',}

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
             print("SHA256 Value",data['sha256_hash'])
             print("SHA2384 Value",data['sha3_384_hash'])
             print("SHA1 Value",data['sha1_hash'])
             print("MD5 Value",data['md5_hash'])
             print("Malware first Seen",data['first_seen'])
             print("Malware Last Seen",data['last_seen'])
             print("Delivey Methods",data['delivery_method'])
             print("Origin County ",data['origin_country'])
    except:
          print("No Result Found ")

#################################################################333
def vt_engines(hash_en_value):
    VTotal_Key = {

    'x-apikey':'568991ceebba95d9b80fa01b234762d9a4965d352b8cb3be795fe9a80cda661c'
    }

    id = hash_en_value
    base_url = f"https://www.virustotal.com/api/v3/files/{id}"
    global res

    try:
       req = requests.get(url=base_url , headers=VTotal_Key)
       res =  req.json()
       alldata  = res.get('data').get('attributes').get("last_analysis_results")
       print(" Virus Total Started")
       for key in alldata:
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
##########################################################################

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
        if key  == 'whois':
            print('############################# WHO IS #############################')
            print('Who is Inof: ')
            print(alldata['whois'])
        if  key == 'last_analysis_stats':
            print('Network Rnage : ',alldata['network'])
        if key == 'last_analysis_results':
            print('############################# SCAN  #############################')
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


##########################################################################
def main():
       
      
       hash_to_search= input("Enter hash for search : ")
       if hash_to_search != "":
          search_for_hash(hash_to_search)
          print("####################################################")
          search_for_hash_bz(hash_to_search)
       else:
           print("Enter A Hash :) ")
           print("Clsoing program ")
           exit
     
if __name__ == '__main__':
     main()