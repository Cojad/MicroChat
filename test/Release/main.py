import define
import interface
import longlink

#测试
def start(name,password):
    interface.InitAll()
    longlink.run(name,password)
    return

if __name__ == "__main__":
    start(define.NAME,define.PASSWORD)