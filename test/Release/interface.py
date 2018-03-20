import xmltodict
import http.client
import urllib
import zlib
import logging
import time
import random
import struct
import string
import define
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

    dns = {'longip':ipLong, 'shortip':ipShort}
    return dns

#登录,参数为账号,密码
def Login(name,password):
    #随机生成16位登录包AesKey
    login_aes_key = bytes(''.join(random.sample(string.ascii_letters + string.digits, 16)), encoding = "utf8")

    #生成ECC key
    if not Util.GenEcdhKey():
        logger.info('生成ECC Key失败!')
        return -1

    #protobuf组包1
    accountRequest = mm_pb2.ManualAuthAccountRequest(
        aes     = mm_pb2.ManualAuthAccountRequest.AesKey(
            len = 16,
            key = login_aes_key
        ),
        ecdh    = mm_pb2.ManualAuthAccountRequest.Ecdh(
            nid = 713,
            ecdhKey = mm_pb2.ManualAuthAccountRequest.Ecdh.EcdhKey(
                len = len(Util.EcdhPubKey),
                key = Util.EcdhPubKey
            )
        ),
        userName = name,
        password1 = Util.GetMd5(password),
        password2 = Util.GetMd5(password)
    )
    #protobuf组包2
    deviceRequest = mm_pb2.ManualAuthDeviceRequest(
        login = mm_pb2.LoginInfo(
            aesKey = login_aes_key,
            uin = 0,
            guid = define.__GUID__ + '\0',          #guid以\0结尾
            clientVer = define.__CLIENT_VERSION__,
            androidVer = define.__ANDROID_VER__,
            unknown = 1,
        ),
        tag2 = mm_pb2.ManualAuthDeviceRequest._Tag2(),
        imei = define.__IMEI__,
        softInfoXml = define.__SOFTINFO__.format(define.__IMEI__,define.__ANDROID_ID__, define.__MANUFACTURER__+" "+define.__MODELNAME__, define.__MOBILE_WIFI_MAC_ADDRESS__, define.__CLIENT_SEQID_SIGN__, define.__AP_BSSID__, define.__MANUFACTURER__,"taurus", define.__MODELNAME__, define.__IMEI__),
        unknown5 = 0,
        clientSeqID = define.__CLIENT_SEQID__,
        clientSeqID_sign = define.__CLIENT_SEQID_SIGN__,
        loginDeviceName = define.__MANUFACTURER__+" "+define.__MODELNAME__,
        deviceInfoXml = define.__DEVICEINFO__.format(define.__MANUFACTURER__, define.__MODELNAME__),
        language = define.__LANGUAGE__,
        timeZone = "8.00",
        unknown13 = 0,
        unknown14 = 0,
        deviceBrand = define.__MANUFACTURER__,
        deviceModel = define.__MODELNAME__+"armeabi-v7a",
        osType = define.__ANDROID_VER__,
        realCountry = "cn",
        unknown22 = 2,                      #Unknown
    )
    
    logger.debug("accountData protobuf数据:" + str(accountRequest.SerializeToString()))
    logger.debug("deviceData protobuf数据:" + str(deviceRequest.SerializeToString()))

    #加密
    reqAccount = Util.compress_and_rsa(accountRequest.SerializeToString())
    reqDevice  = Util.compress_and_aes(deviceRequest.SerializeToString(),login_aes_key)

    logger.debug("加密后数据长度:reqAccount={},reqDevice={}".format(len(reqAccount),len(reqDevice[0])))
    logger.debug("加密后reqAccount数据:" + str(reqAccount))
    logger.debug("加密后reqDevice数据:" + str(reqDevice[0]))

    #封包包体
    subheader = b''
    subheader += struct.pack(">I",len(accountRequest.SerializeToString()))          #accountData protobuf长度
    subheader += struct.pack(">I",len(deviceRequest.SerializeToString()))           #deviceData protobuf长度
    subheader += struct.pack(">I",len(reqAccount))                                  #accountData RSA加密后长度
    body   =  subheader + reqAccount + reqDevice[0]                                 #包体由头信息、账号密码加密后数据、硬件设备信息加密后数据3部分组成
    
    #封包包头
    header = bytearray(0)
    header += bytes([0])                                                            #最后2bit：02--包体不使用压缩算法;前6bit:包头长度,最后计算                                        #
    header += bytes([((0x7<<4) + 0xf)])                                             #07:RSA加密算法  0xf:cookie长度
    header += struct.pack(">I",define.__CLIENT_VERSION__)                           #客户端版本号 网络字节序
    header += bytes([0]*4)                                                          #uin
    header += bytes([0]*15)                                                         #coockie
    header += encoder._VarintBytes(701)                                             #cgi type
    header += encoder._VarintBytes(len(body))                                       #body 压缩前长度
    header += encoder._VarintBytes(len(body))                                       #body 压缩后长度(登录包不需要压缩body数据)
    header += struct.pack(">B",define.__LOGIN_RSA_VER__)                            #RSA秘钥版本
    header += b'\x01\x02'                                                           #Unknown Param
    header[0] = (len(header)<<2) + 2                                                #包头长度

    #组包
    logger.debug('包体数据:' + str(body))
    logger.debug('包头数据:' + str(header))
    senddata = header + body
    
    #发包
    loginRetBytes = Util.mmPost('/cgi-bin/micromsg-bin/manualauth',senddata)
    logger.debug('返回数据:' + str(loginRetBytes))

    #解包
    loginRes = mm_pb2.ManualAuthResponse()
    loginRes.result.code = -1
    loginRes.ParseFromString(Util.UnPack(loginRetBytes,login_aes_key))
     
    #登录异常处理
    if -301 == loginRes.result.code:                        #DNS解析失败,请尝试更换idc
        logger.info('登陆结果:\ncode:{}\n请尝试更换DNS重新登陆!'.format(loginRes.result.code))
    elif -106 == loginRes.result.code:                      #需要在IE浏览器中滑动操作解除环境异常/扫码、短信、好友授权(滑动解除异常后需要重新登录一次)
        logger.info('登陆结果:\ncode:{}\nError msg:{}\n'.format(loginRes.result.code,loginRes.result.err_msg.msg[loginRes.result.err_msg.msg.find('<Content><![CDATA[')+len('<Content><![CDATA['):loginRes.result.err_msg.msg.find(']]></Content>')]))
        #打开IE,完成授权
        logger.info('请在浏览器授权后重新登陆!')
        Util.OpenIE(loginRes.result.err_msg.msg[loginRes.result.err_msg.msg.find('<Url><![CDATA[')+len('<Url><![CDATA['):loginRes.result.err_msg.msg.find(']]></Url>')])
    elif loginRes.result.code:                              #其他登录错误
        logger.info('登陆结果:\ncode:{}\nError msg:{}\n'.format(loginRes.result.code,loginRes.result.err_msg.msg[loginRes.result.err_msg.msg.find('<Content><![CDATA[')+len('<Content><![CDATA['):loginRes.result.err_msg.msg.find(']]></Content>')]))
    else:                                                   #登陆成功
        #密钥协商
        Util.sessionKey = Util.aesDecrypt(loginRes.authParam.session.key,Util.DoEcdh(loginRes.authParam.ecdh.ecdhKey.key))
        #保存uin/wxid
        Util.uin = loginRes.authParam.uin
        Util.wxid = loginRes.accountInfo.wxId
        logger.info('登陆成功!\nsession_key:{}\nuin:{}\nwxid:{}\nnickName:{}\nalias:{}'.format(Util.sessionKey,Util.uin,Util.wxid,loginRes.accountInfo.nickName,loginRes.accountInfo.Alias))

    return loginRes.result.code

#首次登录设备初始化
def new_init():
    #protobuf组包
    new_init_request = mm_pb2.NewInitRequest(
        login = mm_pb2.LoginInfo(
            aesKey =  Util.sessionKey,
            uin = 0,
            guid = define.__GUID__ + '\0',          #guid以\0结尾
            clientVer = define.__CLIENT_VERSION__,
            androidVer = define.__ANDROID_VER__,
            unknown = 1,
        ),
        wxid = Util.wxid,
        tag3 = mm_pb2.mmStr(),
        tag4 = mm_pb2.mmStr(),
        language = define.__LANGUAGE__,
    )
    #组包
    send_data = Util.pack(new_init_request.SerializeToString(),139)

    #发包
    ret_bytes = Util.mmPost('/cgi-bin/micromsg-bin/newinit',send_data)
    logger.debug('返回数据:' + str(ret_bytes))

    #解包
    res = mm_pb2.NewInitResponse()
    res.ParseFromString(Util.UnPack(ret_bytes))

    #newinit后保存sync key
    Util.sync_key = res.synckeybytes.key
    logger.debug('sync key len:{}\ndata:{}'.format(res.synckeybytes.len, Util.b2hex(res.synckeybytes.key)))

    #初始化数据
    logger.debug('tag7数量:{}'.format(res.cntList))

    #未读消息
    for i in range(res.cntList):
        if 5 == res.tag7[i].type:                           #未读消息
            msg = mm_pb2.Msg()
            msg.ParseFromString(res.tag7[i].data.data)
            if 10002 == msg.type or 9999 == msg.type:       #过滤系统垃圾消息
                continue
            else:
                logger.info('收到新消息:\ncreate utc time:{}\ntype:{}\nfrom:{}\nto:{}\nraw data:{}\nxml data:{}'.format(msg.createTime, msg.type, msg.from_id.id, msg.to_id.id, msg.raw.content, msg.xmlContent))
    
    return

#初始化python模块    
def InitAll():
    Util.initLog()
    Util.ip = GetDns()


"""
#登录测试
if __name__ == "__main__":
    InitAll()
    if not Login('13112345678','123456'):
        #首次登录初始化
        new_init()
"""

