### vulnapi

```bash
podman build -t vulnapi .

podman run -it --name vulnapi vulnapi

# example
vulnapi discover api http://rest.vulnweb.com

# output
560168f54374:~$ vulnapi discover api http://rest.vulnweb.com
 100% |████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████| (6/6)
|     TYPE      |              URL              |
|---------------|-------------------------------|
| Exposed Files | http://rest.vulnweb.com/docs/ |


| TECHNOLOGIE/SERVICE |           VALUE           |
|---------------------|---------------------------|
| Language            | PHP:7.1.26                |
| Operating System    | Debian                    |
| Server              | Apache HTTP Server:2.4.25 |
```

Usage:

```bash
Usage:
  vulnapi [command]

Available Commands:
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  jwt         Generate JWT tokens
  scan        API Scan
  serve       Start the server

Flags:
  -h, --help          help for vulnapi
      --sqa-opt-out   Opt out of sending anonymous usage statistics and crash reports to help improve the tool

Use "vulnapi [command] --help" for more information about a command.

# examples
vulnapi scan curl [API_URL] [CURL_OPTIONS]

vulnapi scan curl -X POST https://api.mysite.com/api \
    -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaWF0IjoxNTE2MjM5MDIyfQ."

echo "[JWT_TOKEN]" | vulnapi scan openapi [PATH_OR_URL_TO_OPENAPI_FILE]

vulnapi scan openapi https://api.mysite.com/.well-known/openapi.json
```
