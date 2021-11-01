# Go-Analyzer
## _Golang ELF Triage_




Go-analyzer automates basic static analysis of Golang compiled ELF binaries. Tasks include:
- Hashing
- String extraction & analysis


## Features

- Calculates MD5,SHA1 & SHA256 hashes
- Parses Go Build Id
- Extraction and ranking of Github resources
- Extraction of plugins, URLs, and suspicious strings
- Writes all ascii and unicode strings to seperate file


Usage

```sh
go_analyzer.py go_binary
```

Output Example

```
****************************************
Filename: linuxshell
MD5: 26fa9afde60e9d1035c4c2df7d8918b4
SHA1: 1d295c9ab120a5a57fa5151a926a49427368d5a1
SHA256: 6845ffef723d4f8e3649f10d2ae41cc4dc6a469c832d656416b703700aec64b6
Go Build Id: m1aJpmnC3UESqhWUXMwp/Z7eRUHB8rOHwwUvAlDuw/Ejm49VVdS7-ZQ91_p49j/-CuSPeF85VoQ4UlaggCz


TOP GITHUB SOURCES**********************
github.com/go-redis/ 943
github.com/ugorji/ 882
github.com/denisenkom/ 369
github.com/lib/ 178
github.com/gin-gonic/ 171
github.com/cretz/ 170
github.com/jlaffaye/ 21
github.com/golang/ 14
github.com/golang-sql/ 5
github.com/mattn/ 3
github.com/gin-contrib/ 3


PARSED PLUGINS**************************
abc-hello/plugin.SetConfig
abc-hello/plugin.Scan
abc-hello/plugin.try
abc-hello/plugin.pluginRun.func2
abc-hello/plugin/plugin.go
abc-hello/plugin.Regist
abc-hello/plugin.SshPassCheck
type..eq.abc-hello/plugin.Plugin
abc-hello/plugin.try.func1
abc-hello/plugin.PostgresPassCheck
abc-hello/plugin.pluginRun
abc-hello/plugin.RedisPassCheck
abc-hello/plugin.Check
abc-hello/plugin.CheckErrs
abc-hello/plugin.StartScan
abc-hello/plugin.pluginRun.func1
type..eq.abc-hello/plugin.References
abc-hello/plugin.Weblogic14882Check
abc-hello/plugin.init.0
abc-hello/plugin.StartScan.func1


PARSED URLS*****************************
http://j.mp/mongos-authInvalid
http://103.209.103.16:26800/ff.sh
http://integerinvalidip_addriscolorkeyslotkeytypelinsertlookup
https://idletimeif-matchif-rangeinfinityinvalid


SUSPICIOUS SUBSTRINGS*******************
* suspicious keyword: keylog
      KeyLogWriter
      writeKeyLog
      ...fig).writeKeyLog
```
