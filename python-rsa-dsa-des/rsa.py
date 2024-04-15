from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Hash import SHA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_phcs1_v1_5
from Crypto.Signature import PKCS1_v1_5 as Signature_pkcs1_v1_5
import base64
import time
import datetime
import json

def write_in_file(str_mess):
    try:
        f = open('RSA.txt','w',encoding='utf-8')
        f.write(str_mess)
        f.close()
        print("文件输出成功！")
    except IOError:
        print('文件加解密出错！！！')

def read_out_file():
    try:
        f = open('RSA.txt','r',encoding = 'utf-8')
        mess = f.read()
        f.close()
        print("文件读取成功！")
        return mess
    except IOError:
        print('文件加解密出错！！！')

#发送者使用接受者的公钥加密
def rsaencrypt(content,pubic_key):
    with open(pubic_key) as f:
        key=f.read()
        rsakey=RSA.importKey(key)
        cipher=Cipher_phcs1_v1_5.new(rsakey)
        cipher_text=base64.b64encode(cipher.encrypt(content.encode('utf-8')))
        # print("rsa-encrypt:",cipher_text.decode('utf-8'))
    return cipher_text.decode('utf-8')

#接受者使用自己的私钥对内容rsa解密
def rsadecrypt(result,private_key):
    with open(private_key) as f:
        key=f.read()
        rsakey=RSA.importKey(key)
        cipher=Cipher_phcs1_v1_5.new(rsakey)
        text=cipher.decrypt(base64.b64decode(result),random_generator)
        # print("rsa-decrypt:",text.decode('utf-8'))
    return text.decode('utf-8')

#发送者使用自己的私钥对内容进行签名
def rsaensign(content,private_key):
    with open(private_key) as f:
        key=f.read()
        rsakey=RSA.importKey(key)
        signer=Signature_pkcs1_v1_5.new(rsakey)
        digest=SHA.new()
        digest.update(message.encode('utf-8'))
        sign=signer.sign(digest)
        signature=base64.b64encode(sign)
        # print("rsa-signature:",signature.decode('utf-8'))
    return signer,signature.decode('utf-8')

#接受者使用发送者的公钥对内容进行验签
def rsadesign(signer,signature,message,public_key):
    with open(public_key) as f:
        key=f.read()
        rsakey=RSA.importKey(key)
        verifier=Signature_pkcs1_v1_5.new(rsakey)
        digest=SHA.new()
        digest.update(message.encode('utf-8'))
        is_verify=signer.verify(digest,base64.b64decode(signature))
        
    return is_verify

    
if __name__ == '__main__':
    random_generator=Random.new().read
    rsa=RSA.generate(2048,random_generator)
    private_pem=rsa.exportKey()
    with open("server-private.pem","wb") as f:
        f.write(private_pem)
    public_pem=rsa.publickey().exportKey()
    with open("server-public.pem","wb") as f:
        f.write(public_pem)
    random_generator=Random.new().read
    rsa=RSA.generate(2111,random_generator)
    private_pem=rsa.exportKey()
    with open("client-private.pem","wb") as f:
        f.write(private_pem)
    public_pem=rsa.publickey().exportKey()
    with open("client-public.pem","wb") as f:
        f.write(public_pem)

    entime,detime,signtime,countacc,countfail=0,0,0,0,0

    message_all=['topoadd.json',"topodel.json","topoupdate.json",
             "reportdata.json","reportevent.json",
             "service.json","config_reply.json",
             "data_save.json","data_request.json","data_del.json",
             "edge_prop_request.json"]
    
    for file_name in message_all:
        # print("open:",file_name)
        with open(file_name,'r',encoding='utf-8') as files:
            #获取json
            data=json.load(files)

        #json转换为字符串
        content=json.dumps(data)
        # print("message is :",content)

        ##签名认证
        message=content
        signstart=time.time()
        signer,signature=rsaensign(message,"server-private.pem")
        is_verify=rsadesign(signer,signature,message,"server-public.pem")
        signend=time.time()
        # print("is_verigy:",is_verify)
        signtime+=signend-signstart
        # print("sign-time:",signend-signstart)

        if is_verify:
            enstart=time.time()
            cipher_text=rsaencrypt(message,"client-public.pem")
            enend=time.time()
            entime+=enend-enstart
            # print("rsa-encrypt:",cipher_text)
            # print("rsa-encrypt-time:",enend-enstart)
            destart=time.time()
            text=rsadecrypt(cipher_text,"client-private.pem")
            deend=time.time()
            detime+=deend-destart
            # print("rsa-decrypt:",text)
            # print("rsa-decrypt-time:",deend-destart)
            if text==message:
                countacc+=1
                iscorrect=True
                print("Success!")
            else:
                iscorrect=False
                countfail+=1
                print("Failure!")
        else:
            iscorrect=False
            print("Authentication Failure")
            countfail+=1
        # print(file_name,"cost time:",signend-signstart+enend-enstart+deend-destart)
        f=open("log-rsa.txt",'a',encoding="utf-8")
        f.write("\n\n")
        f.write(str(datetime.datetime.today()))
        f.write("\nopen-json:")
        f.write(file_name)
        f.write("\noriginal message is:")
        f.write(content)
        f.write("\nis_verify:")
        f.write(str(is_verify))
        f.write("\nsign-time:")
        f.write(str(signend-signstart))
        f.write("\nencrypt:")
        f.write(str(cipher_text))
        f.write("\nencrypt-time:")
        f.write(str(enend-enstart))
        f.write("\ndecrypt:")
        f.write(str(text))
        f.write("\ndecrypt-time:")
        f.write(str(deend-destart))
        f.write("\nis Success?:")
        f.write(str(iscorrect))
        f.write("\ntime-all:")
        f.write(str(signend-signstart+enend-enstart+deend-destart))
        f.write("\n")
        f.close()
        print()
    f=open("log-rsa.txt",'a')
    f.write("\nall json accuracy:")
    f.write(str(countacc/(countacc+countfail)))
    f.write("\nall json cost time:")
    f.write(str(signtime+entime+detime))
    f.close()
    print("all json accuracy:",countacc/(countacc+countfail))
    print("all json cost time:",signtime+entime+detime)

    # with open('message.txt','r') as f:
    #     line=f.readline()
    #     while line:
    #         print("original message:",line.strip())
    #         message=line.strip()
    #         signstart=time.time()
    #         signer,signature=rsaensign(message,"server-private.pem")
    #         is_verify=rsadesign(signer,signature,message,"server-public.pem")
    #         signend=time.time()
    #         print("is_verigy:",is_verify)
    #         signtime+=signend-signstart
    #         print("sign-time:",signend-signstart)
    #         if is_verify:
    #             enstart=time.time()
    #             cipher_text=rsaencrypt(message,"client-public.pem")
    #             enend=time.time()
    #             entime+=enend-enstart
    #             print("rsa-encrypt:",cipher_text)
    #             print("rsa-encrypt-time:",enend-enstart)
    #             destart=time.time()
    #             text=rsadecrypt(cipher_text,"client-private.pem")
    #             deend=time.time()
    #             detime+=deend-destart
    #             print("rsa-decrypt:",text)
    #             print("rsa-decrypt-time:",deend-destart)
    #             if text==message:
    #                 countacc+=1
    #                 print("Success!")
    #             else:
    #                 countfail+=1
    #                 print("Failure!")
    #         else:
    #             print("Authentication Failure")
    #             countfail+=1
    #         print()
    #         line=f.readline()
    # accuracy=(countacc)/(countacc+countfail)
    # print("message.txt-accuracy:",accuracy)
    # print("message.txt-sign-time:",signtime)
    # print("message.txt-encrypt-time:",entime)
    # print("message.txt-decrypt-time:",detime)
    # print("message.txt-all-time:",signtime+entime+detime)


    

