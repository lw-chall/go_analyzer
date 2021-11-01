import os
import re
from collections import namedtuple
import sys
import hashlib


ASCII_BYTE = rb" !\"#\$%&\'\(\)\*\+,-\./0123456789:;<=>\?@ABCDEFGHIJKLMNOPQRSTUVWXYZ\[\]\^_`abcdefghijklmnopqrstuvwxyz\{\|\}\\\~\t"
String = namedtuple("String", ["s", "offset"])

suswords = ['brute','keylog','stealer']#add suspicious keywords here

githubs = {}
allurls = set()
plugins = set()

sussubstrings = {}
susoffset = 10

strings_ = []

def ascii_strings(buf, n=4):
    reg = rb"([%s]{%d,})" % (ASCII_BYTE, n)
    ascii_re = re.compile(reg)
    for match in ascii_re.finditer(buf):
        yield String(match.group().decode("ascii"), match.start())

def unicode_strings(buf, n=4):
    reg = rb"((?:[%s]\x00){%d,})" % (ASCII_BYTE, n)
    uni_re = re.compile(reg)
    for match in uni_re.finditer(buf):
        try:
            yield String(match.group().decode("utf-16"), match.start())
        except UnicodeDecodeError:
            pass


def analyze(filepath):

    strings_ = []

    unistrings_ = []

    strings_offsets = []
    unistrings_offsets = []


    strings_output = filepath +'_strings.txt'

    output = open(strings_output,'w')
    
    with open(filepath, 'rb') as f:


        b = f.read()

        md5Hash = hashlib.md5(b)
        md5Hashed = md5Hash.hexdigest()
        sha1Hash = hashlib.sha1(b)
        sha1HashHashed = sha1Hash.hexdigest()
        sha256Hash = hashlib.sha256(b)
        sha256HashHashed = sha256Hash.hexdigest()

        print('\n')

        print('****************************************')

        print('Filename:',filepath)

        print('MD5:',md5Hashed)

        print('SHA1:',sha1HashHashed)

        print('SHA256:',sha256HashHashed)

        output.write(('filename:'+filepath))
        output.write('\n')        
        output.write(('md5:'+md5Hashed))
        output.write('\n')
        output.write(('sha1:'+sha1HashHashed))
        output.write('\n')
        output.write(('sha256:'+sha256HashHashed))
        output.write('\n')
        output.write('strings:')
        output.write('\n')
        output.write('\n')
        output.write('\n')

    for s in ascii_strings(b, n=4):
        str_ = ('0x{:x}: {:s}'.format(s.offset, s.s))
        #print(str_)
        strings_offsets.append(str_)
        strings_.append(s.s)


    for s in unicode_strings(b, n=4):
        str_ = ('0x{:x}: {:s}'.format(s.offset, s.s))

        unistrings_offsets.append(str_)
        strings_.append(s.s)

    found_build_id = 0

    for line in strings_:
        line = line.strip()
        if len(line) == 83:
            print('Go Build Id:',line)
            found_build_id = 1
            break

    if found_build_id != 1:
        print("* couldn't find Go build id!")

    else:
        print('\n')

        
        for line in strings_:
            line = line.strip()


            ##################### github parse
            if 'github.com/' in line:
                uri = line.split('github.com/')[1]

                paths = uri.split('/')
                username = paths[0]
                try:
                    repo_funcs = paths[1]
                    full = 'github.com/'+username+'/'


                    if full not in githubs:
                        
                        githubs[full] = set()
                        githubs[full].add(str(paths))
                    else:
                        githubs[full].add(str(paths))
                except:
                    pass


            ##################### plugin parse
            if '/plugin.' in line:
                plugins.add(line)


            ##################### URL parse

            urls = re.findall(r'(https?://\S+)', line)
            for url in urls:
                allurls.add(url)
                
            ##################### SUS parse


            for sus in suswords:

                linelower = line.lower()

                if sus in line.lower():


                    index = linelower.index(sus)

                    loffset = index-susoffset
                    roffset = index+len(sus)+susoffset

                    if loffset > 0 and roffset < len(linelower):
                        substring = '...'+line[loffset:roffset]+'...'
                    elif loffset < 0 and roffset < len(linelower):
                        substring = line[loffset:roffset]+'...'
                    elif loffset > 0 and roffset > len(linelower):
                        substring = '...'+line[loffset:]
                    else:
                        substring = line

                    if sus not in sussubstrings:
                        sussubstrings[sus] = set()
                        sussubstrings[sus].add(substring)
                    else:
                        sussubstrings[sus].add(substring)


        github_ranks = []
                        
        for github,func in githubs.items():
            if len(func) >= 1:
                #print github,len(func)
                github_ranks.append([len(func),github])


        github_ranks = list(reversed(sorted(github_ranks)))


        if len(github_ranks) == 0:
            print('obfuscated file?')
            
        print('TOP GITHUB SOURCES**********************')
        for g in github_ranks:

            print(g[1],g[0])

        print('\n')
        print('PARSED PLUGINS**************************')
        for p in plugins:
            print(p)

        print('\n')
        print('PARSED URLS*****************************')

        for url in allurls:
            print(url)

        print('\n')
        print('SUSPICIOUS SUBSTRINGS*******************')
        for sus,substrings in sussubstrings.items():
            print('* suspicious keyword:',sus)
            for sub in substrings:
                print('     ',sub)


    for s in strings_offsets:
        output.write(s)
        output.write('\n')
    output.write('\n')
    output.write('unicode strings:')
    output.write('\n')
    output.write('\n')
    output.write('\n')
    for s in unistrings_offsets:
        output.write(s)
        output.write('\n')

    print('\n')

    print('** wrote all strings to ',strings_output)
    
if __name__ == '__main__':

    errors = 0

    if len(sys.argv) == 2:

        go_binary = sys.argv[1]

        analyze(go_binary)

       
    else:
        print("Needs argument!")
        print("usage - go_analyzer.py go_binary")
        exit(1)

        
