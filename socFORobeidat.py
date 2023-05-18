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


def main():
       hash_to_search= input("Enter hash for search : ")
       if hash_to_search != "":
          search_for_hash(hash_to_search)
       else:
           print("Enter A Hash :) ")
           print("Clsoing program ")
           exit

if __name__ == '__main__':
     main()