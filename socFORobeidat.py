import requests 
import json

def search_for_hash(hash):
    print("Hash searching has been started ....\n")
    threat_fox_apikey ={
     "API-KEY": "Put threatfox api key",
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
    headers = {'API-KEY': 'Put Malwarebazar API key',}

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
    except:
          print("No Result Found ")

#################################################################333
def vt_engines(hash_en_value):
    VTotal_Key = {

    'x-apikey':'PUT virustotal API key'
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
    VTotal_Key = {'x-apikey':'VirusTotal API key'}

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




def MT(hash_val):
    url = f"https://api.metadefender.com/v4/hash/{hash_val}"

    headers = {
        'apikey': "Put meta defnder apikey"
    }

    response = requests.request("GET", url, headers=headers)

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


###########################################################################



import requests
import json

import requests
import json

def VTF (hash_val):

    VTotal_Key = {'x-apikey':'Virustotla APi key'}

    id = hash_val
    base_url = f"https://www.virustotal.com/api/v3/files/{id}"


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
        #elif key == 'signature_info':
        #    print("Signature Information :") 
        #    for k in alldata['signature_info']:
        #      print("\t",alldata['signature_info'][k]) 
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

    subdata  =  res.get('links')
    print("read full report ",subdata)

    subdata1 = res.get('type')
    print("Type" , subdata1)


###########################################################################
def main():
  
    
       
       
       hash_to_search= input("Enter hash for search : ")
       hash_to_search = hash_to_search.replace(" ","")
       if hash_to_search != "":
          print("################ Virus Total Engine ################")
          VTF(hash_to_search)
          print("################ Threat Fox Engine  ################")
          search_for_hash(hash_to_search)
          print("################    Malware   Bazar ################")
          search_for_hash_bz(hash_to_search)
          print()
          print("################### Meta Engine    ####################")
          print()
          MT(hash_to_search)
          #print("################# Virus Total Engines ##############")
          #vt_engines(hash_to_search)
       else:
           print("Enter A Hash :) ")
           print("Clsoing program ")
           exit
       
   
if __name__ == '__main__':
     main()
