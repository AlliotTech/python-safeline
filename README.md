Python SafeLine is a python wrapper for the `SafeLine WAF`  
### Install  
``` shell  
pip install safeline  
```

### Example  
``` python3  
import safeline

if __name__ == '__main__':
    BASE_URL = "https://xxx.com"
    API_TOKEN = "IX62FxxxxxxxxxxW2WB4C"

    waf = SafeLine(BASE_URL,
                   API_TOKEN
                   )

    # list all certification  
    print(waf.certification.list)
    
    # certification 
    waf.certification.update(cert_id, crt, key)
    
    # ip_group
    waf.ip_group.update(ipgroup_id, ipgroup_list)

```