import logging
import http.client
import time
import hashlib
import zlib
import struct
import os,sys
import webbrowser
import ctypes
import subprocess
import define
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
from google.protobuf.internal import decoder,encoder
from ctypes import * 

################################全局变量################################
#日志级别(INFO级别不输出debug信息)
__LOG_LEVEL__ = logging.INFO  
logger = logging.getLogger("mmTest")
                                      
#cgi http头
headers = {
            "Accept" : "*/*",
            "Cache-Control" : "no-cache",
            "Connection" : "close",
            "Content-type" : "application/octet-stream",
            "User-Agent": "MicroMessenger Client"
}

#长短链接默认地址;调用GetDNS()接口后会存放服务器解析的长短链接ip
ip = {'longip':'long.weixin.qq.com', 'shortip':'short.weixin.qq.com'}

#ECDH key
EcdhPriKey = b''
EcdhPubKey = b''

#session key(封包解密时的aes key/iv)
sessionKey = b''

#uin
uin = 0

#wxid
wxid = ''

########################################################################

#日志初始化
def initLog():    
    logger.setLevel(__LOG_LEVEL__)
    hterm =  logging.StreamHandler()
    hterm.setLevel(__LOG_LEVEL__)
    hfile = logging.FileHandler(time.strftime("%Y-%m-%d", time.localtime()) + ".log")
    hfile.setLevel(__LOG_LEVEL__)
    formatter = logging.Formatter('[%(asctime)s][%(levelname)s]: %(message)s')
    hterm.setFormatter(formatter)
    hfile.setFormatter(formatter)
    logger.addHandler(hterm)
    logger.addHandler(hfile)

#md5
def GetMd5(src):
    m1 = hashlib.md5()   
    m1.update(src.encode('utf-8'))
    return m1.hexdigest()

#padding
pad     = lambda s: s + bytes([16 - len(s) % 16] * (16 - len(s) % 16))
unpad   = lambda s : s[0:(len(s) - s[-1])]

#先压缩后AES-128-CBC加密
def compress_and_aes(src,key):
    compressData = zlib.compress(src)
    aes_obj = AES.new(key, AES.MODE_CBC, key)     #IV与key相同
    encrypt_buf=aes_obj.encrypt(pad(compressData))
    return (encrypt_buf,len(compressData))        #需要返回压缩后protobuf长度,组包时使用

#不压缩AES-128-CBC加密
def aes(src,key):
    aes_obj = AES.new(key, AES.MODE_CBC, key)     #IV与key相同
    encrypt_buf=aes_obj.encrypt(pad(src))
    return encrypt_buf

#先压缩后RSA加密
def compress_and_rsa(src):
    compressData = zlib.compress(src)
    rsakey = RSA.construct((int(define.__LOGIN_RSA_VER158_KEY_N__,16),define.__LOGIN_RSA_VER158_KEY_E__))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    encrypt_buf = cipher.encrypt(compressData)
    return encrypt_buf

#不压缩RSA2048加密
def rsa(src):
    rsakey = RSA.construct((int(define.__LOGIN_RSA_VER158_KEY_N__,16),define.__LOGIN_RSA_VER158_KEY_E__))
    cipher = Cipher_pkcs1_v1_5.new(rsakey)
    encrypt_buf = cipher.encrypt(src)
    return encrypt_buf

#AES-128-CBC解密解压缩
def decompress_and_aesDecrypt(src,key):
    aes_obj = AES.new(key, AES.MODE_CBC, key)     #IV与key相同
    decrypt_buf = aes_obj.decrypt(src)
    return zlib.decompress(unpad(decrypt_buf))

#AES-128-CBC解密
def aesDecrypt(src,key):
    aes_obj = AES.new(key, AES.MODE_CBC, key)     #IV与key相同
    decrypt_buf = aes_obj.decrypt(src)
    return unpad(decrypt_buf)

#HTTP短链接发包
def mmPost(cgi,data):
    conn = http.client.HTTPConnection(ip['shortip'], timeout=10)
    conn.request("POST",cgi,data,headers)
    response = conn.getresponse().read()
    conn.close()
    return response

#解包
def UnPack(src,key):
    if len(src) < 20:
        return b''
    #解析包头   
    nCur= 0
    if src[nCur] == '\xbf':
        nCur += 1                                                         #跳过协议标志位
    nLenHeader = src[nCur] >> 2                                           #包头长度
    bUseCompressed = (src[nCur] & 0x3 == 1)                               #包体是否使用压缩算法:01使用,02不使用
    nCur += 1
    nDecryptType = src[nCur] >> 4                                         #解密算法(固定为AES解密): 05 aes解密 / 07 rsa解密
    nLenCookie = src[nCur] & 0xf                                          #cookie长度
    nCur += 1
    nCur += 4                                                             #服务器版本(当前固定返回4字节0)
    uin= struct.unpack('>I',src[nCur:nCur+4])[0]                          #uin
    nCur += 4
    cookie = src[nCur:nCur+nLenCookie]                                    #cookie
    nCur += nLenCookie
    (nCgi,nCur) = decoder._DecodeVarint(src,nCur)                         #cgi type
    (nLenProtobuf,nCur) = decoder._DecodeVarint(src,nCur)                 #压缩前protobuf长度
    (nLenCompressed,nCur) = decoder._DecodeVarint(src,nCur)               #压缩后protobuf长度
    logger.debug('包头长度:{}\n是否使用压缩算法:{}\n解密算法:{}\ncookie长度:{}\nuin:{}\ncookie:{}\ncgi type:{}\nprotobuf长度:{}\n压缩后protobuf长度:{}'.format(nLenHeader, bUseCompressed, nDecryptType, nLenCookie, uin, str(cookie), nCgi, nLenProtobuf, nLenCompressed))
    #对包体aes解密解压缩
    body = src[nLenHeader:]                                               #取包体数据
    if bUseCompressed:
        protobufData = decompress_and_aesDecrypt(body,key)
    else:
        protobufData = aesDecrypt(body,key)
    logger.debug('解密后数据:%s' % str(protobufData))
    return protobufData

#退出程序
def ExitProcess():
    os.system("pause")
    logger.info('===========bye===========')
    sys.exit()

#使用IE浏览器访问网页(阻塞)
def OpenIE(url):
    subprocess.call('"C:\Program Files\Internet Explorer\iexplore.exe" "{}"'.format(url))

#使用c接口生成ECDH本地密钥对
def GenEcdhKey():
    global EcdhPriKey,EcdhPubKey
    #载入c模块
    loader = ctypes.cdll.LoadLibrary  
    lib = loader("./ecdh.dll")   
    #申请内存
    priKey = bytes(bytearray(2048))         #存放本地DH私钥
    pubKey = bytes(bytearray(2048))         #存放本地DH公钥
    lenPri = bytes(bytearray(4))            #存放本地DH私钥长度
    lenPub = bytes(bytearray(4))            #存放本地DH公钥长度
    #转成c指针传参
    pri = c_char_p(priKey)
    pub = c_char_p(pubKey)
    pLenPri = c_char_p(lenPri)
    pLenPub = c_char_p(lenPub)
    #secp224r1 ECC算法
    nid = 713
    #c函数原型:bool GenEcdh(int nid, unsigned char *szPriKey, int *pLenPri, unsigned char *szPubKey, int *pLenPub);
    bRet = lib.GenEcdh(nid, pri, pLenPri, pub, pLenPub)
    if bRet:
        #从c指针取结果
        lenPri = struct.unpack('<I',lenPri)[0]
        lenPub = struct.unpack('<I',lenPub)[0]
        EcdhPriKey = priKey[:lenPri]
        EcdhPubKey = pubKey[:lenPub]
    return bRet

#密钥协商
def DoEcdh(serverEcdhPubKey):
    EcdhShareKey = b''
    #载入c模块
    loader = ctypes.cdll.LoadLibrary  
    lib = loader("./ecdh.dll")
    #申请内存
    shareKey = bytes(bytearray(2048))           #存放密钥协商结果
    lenShareKey = bytes(bytearray(4))           #存放共享密钥长度
    #转成c指针传参
    pShareKey = c_char_p(shareKey)
    pLenShareKey = c_char_p(lenShareKey)
    pri = c_char_p(EcdhPriKey)
    pub = c_char_p(serverEcdhPubKey)
    #secp224r1 ECC算法
    nid = 713
    #c函数原型:bool DoEcdh(int nid, unsigned char * szServerPubKey, int nLenServerPub, unsigned char * szLocalPriKey, int nLenLocalPri, unsigned char * szShareKey, int *pLenShareKey);
    bRet = lib.DoEcdh(nid, pub, len(serverEcdhPubKey), pri, len(EcdhPriKey), pShareKey, pLenShareKey)
    if bRet:
        #从c指针取结果
        lenShareKey = struct.unpack('<I',lenShareKey)[0]
        EcdhShareKey = shareKey[:lenShareKey]
    return EcdhShareKey



