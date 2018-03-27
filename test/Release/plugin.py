import json
import define
import interface
import mm_pb2
import Util
from Util import logger

#图灵机器人接口
TULING_HOST   = 'openapi.tuling123.com'
TULING_API    = 'http://openapi.tuling123.com/openapi/api/v2'
#图灵机器人key
TULING_KEY    = '460a124248234351b2095b57b88cffd2'

#机器人自动回复黑名单(wxid)
tuling_blacklist = ['weixin',]

#图灵机器人
def tuling_robot(msg):
    #过滤自动回复wxid
    for i in tuling_blacklist:
        if msg.from_id.id == i:
            return
    #使用图灵接口获取自动回复信息
    data = {
        'reqType':0,
        'perception':
        {
            "inputText": 
            {
                "text": msg.raw.content
            },
        },
        'userInfo': 
        {
            "apiKey": TULING_KEY,
            "userId": Util.GetMd5(msg.from_id.id)
        }
    }
    try:
        robot_ret = eval(Util.post(TULING_HOST,TULING_API,json.dumps(data)).decode())
        logger.debug('tuling api 返回:{}'.format(robot_ret))
        #自动回消息
        interface.new_send_msg(msg.from_id.id,robot_ret['results'][0]['values']['text'].encode(encoding="utf-8"))
    except:
        logger.info('tuling api 调用异常!')
    return

#处理消息
def dispatch(msg):
    #自动回复文字消息
    if 1 == msg.type:
        tuling_robot(msg)
    return