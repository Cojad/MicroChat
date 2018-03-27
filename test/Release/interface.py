import http.client
import logging
import time
import random
import struct
import string
import urllib
import xmltodict
import zlib
import define
import business
import Util
import mm_pb2
from Util import logger
from google.protobuf.internal import decoder,encoder


#获取长短链接Ip
def GetDns():
    headers = {
            "Accept" : "*/*",
            "Accept-Encoding" : "deflate",
            "Cache-Control" : "no-cache",
            "Connection" : "close",
            "Content-type" : "application/octet-stream",
            "User-Agent": "MicroMessenger Client"
    }
    conn = http.client.HTTPConnection('dns.weixin.qq.com', timeout=10)
    conn.request("GET",'/cgi-bin/micromsg-bin/newgetdns',"",headers)
    response = conn.getresponse()
    data = zlib.decompress(response.read(), -zlib.MAX_WBITS)
    conn.close()

    parsed = xmltodict.parse(data,encoding='utf-8')

    ipLong  = ''
    ipShort = ''
    
    #取长短链接ip,默认使用服务器返回的第一个ip
    dictDomain = parsed['dns']['domainlist']['domain']
    for i in range(len(dictDomain)):
        if dictDomain[i]['@name'] == 'szlong.weixin.qq.com':
            ipLong = dictDomain[i]['ip'][0]
        elif dictDomain[i]['@name'] == 'szshort.weixin.qq.com':
            ipShort = dictDomain[i]['ip'][0]

    logger.info('长链接ip:' + ipLong + ',短链接ip:' + ipShort)

    return {'longip':ipLong, 'shortip':ipShort}

#登录,参数为账号,密码
def Login(name,password):
    #组包
    (senddata,login_aes_key) = business.login_req2buf(name,password)
   
    #发包
    ret_bytes = Util.mmPost('/cgi-bin/micromsg-bin/manualauth',senddata)
    logger.debug('返回数据:' + str(ret_bytes))

    #解包
    return business.login_buf2Resp(ret_bytes,login_aes_key)

#首次登录设备初始化
def new_init():
    #组包
    send_data = business.new_init_req2buf()

    #发包
    ret_bytes = Util.mmPost('/cgi-bin/micromsg-bin/newinit',send_data)
    logger.debug('new_init返回数据:' + str(ret_bytes))

    #解包
    return business.new_init_buf2resp(ret_bytes)  

#同步消息
def new_sync():
    #组包
    send_data = business.new_sync_req2buf()

    #发包
    ret_bytes = Util.mmPost('/cgi-bin/micromsg-bin/newsync',send_data)
    logger.debug('new_sync返回数据:' + str(ret_bytes))

    #解包
    return business.new_sync_buf2resp(ret_bytes)  

#发消息
def new_send_msg(to_wxid,msg_content,msg_type = 1):
    #组包
    send_data = business.new_send_msg_req2buf(to_wxid,msg_content,msg_type)

    #发包
    ret_bytes = Util.mmPost('/cgi-bin/micromsg-bin/newsendmsg',send_data)
    logger.debug('new_send_msg返回数据:' + Util.b2hex(ret_bytes))

    #解包
    return business.new_send_msg_buf2resp(ret_bytes)


#初始化python模块    
def InitAll():
    Util.initLog()
    Util.ip = GetDns()
    #初始化ECC key
    if not Util.GenEcdhKey():
        logger.info('初始化ECC Key失败!')
        Util.ExitProcess()
