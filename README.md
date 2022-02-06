# VirusTotal users comments realtime monitoring

_vt_users_monitoring_ is a simple python routine designed to monitore _VirusTotal_ user accounts comments. It returns file hashs and basic details. Results can be filtered depending on comment's text content. Works with both _VirusTotal_ free end enterprise API.  

## Configuration

```

users_monitoring:
    vt_api_key: '<VT_API_KEY>'
    listener:
      - user: 'Username'
        filters: ['optional','array','of','items','to','search','in','comment','text'] # boolean OR query
        output_comment_regex: '' # optional - extract part of comment message
```

## Dependencies

* Python 3.x
* PyYAML

use `pip install -r requirements.txt` for easy install 

## Output

_vt_users_monitoring_ generate a CSV file every hour like this:

```

"md5","sha1","sha256","malicious_scoring","first_submission","times_submitted","in_user_comments","match_details","virustotal_url"
"042fa362453080ee25549a67f09abede","b7a6fec85cdc683b6d4ed11f66954b384ebd80bc","50547630f5698f89d6bc02bd596e2ed7937c720885e38eb8c293bb7a63b55155","55","2022-02-06 12:26:26","1","thor","RULE: SUSP_Encoded_GetCurrentThreadId","https://www.virustotal.com/api/v3/files/50547630f5698f89d6bc02bd596e2ed7937c720885e38eb8c293bb7a63b55155"
"f365f7962f4769de859ddf95102e15b4","b99b7f027fceddba2f1101c91480a82abc3b89b8","10b788dc7d82a0cf8a8dd54027c6bd0f3e57ca360b42a910e15226ce09c57592","52","2022-02-06 12:26:27","1","thor","RULE: Suspicious_malformed_PE_Header","https://www.virustotal.com/api/v3/files/10b788dc7d82a0cf8a8dd54027c6bd0f3e57ca360b42a910e15226ce09c57592"
"851d985bb9ddb84bc2b2991ed55dd818","bddf56ed2dbb7d30152d5122cc80149df0bec9ed","8604bca74ae66ec376783bd70f45e7c0e32a2ac916da213f5cc99d3da9297726","53","2022-02-06 12:26:38","1","thor","RULE: Typical_Malware_String_Transforms","https://www.virustotal.com/api/v3/files/8604bca74ae66ec376783bd70f45e7c0e32a2ac916da213f5cc99d3da9297726"
"0210c87346312596008b853dcbfe9f37","a00ba0753c749045d80d6d1ffd968de80ea2a303","e22223f7bc9d3b04e771b0a3f1b5015a1cbb17bbf20e890f1232ffdaf70fd681","54","2022-02-06 12:26:25","1","thor","RULE: Suspicious_malformed_PE_Header","https://www.virustotal.com/api/v3/files/

```
