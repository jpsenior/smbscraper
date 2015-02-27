#!/usr/bin/python
# Grab credentials from a second credentials store.
# The MIT License (MIT)
#
# Copyright (c) 2015 JP Senior jp.senior@gmail.com
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#

import credentials
import re
import tempfile
import socket
import sys
from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure
from smb.base import NotConnectedError

def sizeof_fmt(num):
    for x in ['bytes','KB','MB','GB','TB']:
        if num < 1024.0:
            return "%3.1f %s" % (num, x)
        num /= 1024.0



#name of the host you want to audit. TODO: Take this as a command line variable?
port=139

debug = False

# Meant for many file extensions
searchexts=['ini','bak','cmd','txt','text','conf','cfg','reg','config','lnk','pif']

#These are search words to look for within these files.
searchstrings={
  'username':r'(?i)user(name)',
  'password':r'(?i)password',
  'version':r'(?i)version',
  'Credit_Card_Track_1':r'(\D|^)\%?[Bb]\d{13,19}\^[\-\/\.\w\s]{2,26}\^[0-9][0-9][01][0-9][0-9]{3}',
  'Credit_Card_Track_2':r'(\D|^)\;\d{13,19}\=(\d{3}|)(\d{4}|\=)',
  'Credit_Card_Track_Data':r'[1-9][0-9]{2}\-[0-9]{2}\-[0-9]{4}\^\d',
  'Mastercard':r'(\D|^)5[1-5][0-9]{2}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)',
  'Visa':r'(\D|^)4[0-9]{3}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)',
  'AMEX':r'(\D|^)(34|37)[0-9]{2}(\ |\-|)[0-9]{6}(\ |\-|)[0-9]{5}(\D|$)',
  'Diners_Club_1':r'(\D|^)30[0-5][0-9](\ |\-|)[0-9]{6}(\ |\-|)[0-9]{4}(\D|$)',
  'Diners_Club_2':r'(\D|^)(36|38)[0-9]{2}(\ |\-|)[0-9]{6}(\ |\-|)[0-9]{4}(\D|$)',
  'Discover':r'(\D|^)6011(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)',
  'JCB_1':r'(\D|^)3[0-9]{3}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\ |\-|)[0-9]{4}(\D|$)',
  'JCB_2':r'(\D|^)(2131|1800)[0-9]{11}(\D|$)',
  'Social_Security_Number_dashes':r'(\D|^)[0-9]{3}\-[0-9]{2}\-[0-9]{4}(\D|$)',
  'Social_Security_Number_spaces':r'(\D|^)[0-9]{3}\ [0-9]{2}\ [0-9]{4}(\D|$)',
}



searchreg='|'.join(searchexts)
p = re.compile(searchreg, re.IGNORECASE)


#initialize the array; very helpful if you keep re-running the script.  This one is a lazy global. JP to fix later.
searchlist={}

def listshares(conn,host):
  print ("%15s %9s %5s %4s %s") % ("Name","Temporary","Special","Type","Comments")
  for s in conn.listShares():
    print ("%15s %9s %5s %4s %s") % (s.name, s.isTemporary, s.isSpecial, s.type, s.comments)
    listfiles(s.name, "",conn,host)



#There is no associative array for smb objects, so let's just pretend here that this actually works.
def listfiles(volume,parent,conn,host):
  if parent=="": print "Listing files within",volume,"on",host
  if debug: print "DEBUG search(" + volume + ',' + parent + ')'
  try:
    for f in conn.listPath(volume, parent):
      if f.filename != '.' and f.filename != '..':
        path = "smb://" + host.lower() + "/" + volume + '/' + parent + f.filename
        if not f.isDirectory and p.search(path):
          searchlist.update({(host,volume,parent + '/' + f.filename):{
            'host':host,
            'volume':volume,
            'alloc_size':f.alloc_size,
            'create_time':f.create_time,
            'file_attributes':f.file_attributes,
            'file_size':f.file_size,
            'path':parent,
            'filename':f.filename,
            'last_access_time':f.last_access_time,
            'last_attr_change_time':f.last_attr_change_time,
            'last_write_time':f.last_write_time,
            'short_name':f.short_name}
        })
          if debug: print "SCRAPING:", path, "matches file extension regular expression"
      if f.isDirectory and f.filename != '.' and f.filename != "..":
        if debug: "DEBUG: Calling search(" + volume + "," + parent + " + " + f.filename + "/)"
        listfiles(volume, parent + f.filename + '/',conn,host)
  except OperationFailure as e:
    if debug: print 'Could not open', parent
    if debug: print e




#This actually scans files.
def scanfiles(files,conn):
  for i in files:
    host = i[0]
    volume = i[1]
    alloc_size = files[i]['alloc_size']
    create_time = files[i]['create_time']
    file_attributes = files[i]['file_attributes']
    file_size = files[i]['alloc_size']
    last_access_time = files[i]['last_access_time']
    path = files[i]['path']
    filename = files[i]['filename']
    last_attr_change_time = files[i]['last_attr_change_time']
    last_write_time = files[i]['last_write_time']
    short_name = files[i]['short_name']
    if debug: print 'SCANNING: %20s %10s %5s %s %s %s ' % (last_write_time, sizeof_fmt(file_size), file_attributes, host, volume, path + '/' + filename)
    file_obj = tempfile.NamedTemporaryFile()
    try:
      file_attr, fsize = conn.retrieveFile(volume, path + '/' + filename, file_obj)
      if debug: print file_obj
      file_obj.seek(0)
      x = 0
      for line in file_obj:
        x = x + 1
        if debug: print "DEBUG LISTFILE: %d: %s" % (x, line)
        for r in searchstrings:
          result=re.search(searchstrings[r], line)
          if result:
            print 'Violation found in file: %20s %10s %5s %s %s %s ' % (last_write_time, sizeof_fmt(file_size), file_attributes, host, volume, path + '/' + filename)
            print 'Found',r,"matching",searchstrings[r],"->", result.group(0)
            print '>',line
      file_obj.close
    except OperationFailure as e:
      if debug: print 'Could not open', path + '/' + filename
      if debug: print e

def scanhost(host,destIP,port):
  #Go for it
  try:
    print "*** Initiating SMB scan for",host,"(" + destIP + ") on port",port
    conn = SMBConnection(credentials.username, credentials.password, credentials.clientname, host, domain=credentials.domainname, use_ntlm_v2=True)

    assert conn.connect(destIP, port)
    listshares(conn,host)
    #volume='SYSVOL'
    #search(volume,'')
    scanfiles(searchlist,conn)
  except NotConnectedError:
    print "Could not connect to server name", host

i=0
for h in sys.argv:
  if not i == 0:
    destIP=socket.gethostbyname(h)
    print h, destIP
    scanhost(h,destIP,port)
  i = i + 1
