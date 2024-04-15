import hashlib
import random
import time
import tools
import json
from DES_BOX import *
import re
import base64
from toporequest import nodeInfo,nodeStatuses,topoadd,topodel,topoupdate

# 获取一个大素数p，满足2**(L-1) < p < 2**L,且L是64的倍数，512 < L < 1024

class Key(object):  # 创建一个素数对象，含有相关的方法

    def __init__(self, count):

        while True:
            q = tools.get_prime(160)
            t = 2 * random.randint(2**(64*n - 161)-1,2**(64*n -160))
            p = q * t + 1
            if tools.Isprime(p):
                break

        while True:  # 获取h,g
            h = random.randint(2, p - 1)
            g = tools.quick_algorithm(h, t, p)
            if g > 1:
                break

        x = random.randint(1, q - 1)  # 私钥

        self.p = p
        self.q = q
        self.t = t  # (p - 1) // q
        self.h = h
        self.g = g
        self.__private_key = x  # 私有变量
        self.open_key = tools.quick_algorithm(g, x, p)

    def puts(self):
        print('p的值为：{}'.format(self.p))
        print('q的值为：{}'.format(self.q))
        print('t的值为：{}'.format(self.t))
        print('h的值为：{}'.format(hex(self.h)))
        print('g的值为：{}'.format(hex(self.g)))
        print('私钥x的值为：{}'.format(hex(self.__private_key)))
        print('公钥y的值为：{}'.format(hex(self.open_key)))

    def sign(self,content):  # 获取r,s 的值
        list_rs = []
        k = random.randint(1, self.q - 1)

        r = tools.quick_algorithm(self.g, k, self.p) % self.q
        list_rs.append(r)
        # 获取消息的杂凑值
        
                
        H_M = hashlib.sha1()
        H_M.update(content.encode('utf8'))
        hm = int(H_M.hexdigest(), 16)

        s = (tools.get_inverse(k, self.q ) * (hm + self.__private_key * r) )% self.q
        list_rs.append(s)

        return list_rs

    def verif(self,list_sign:list,content):

        w = tools.get_inverse(list_sign[1],self.q) % self.q

        H_M = hashlib.sha1()
        H_M.update(content.encode('utf8'))
        hm = int(H_M.hexdigest(), 16)

        u1 = hm * w % self.q
        u2 = list_sign[0] * w % self.q
        v = ((tools.quick_algorithm(self.g,u1,self.p) * tools.quick_algorithm(self.open_key,u2,self.p)) % self.p) % self.q
        if v == list_sign[0]:
            is_verify=True
        else:
            is_verify=False
        
        return is_verify

def write_in_file(str_mess):
    try:
        f = open('DES.txt','w',encoding='utf-8')
        f.write(str_mess)
        f.close()
        # print("文件输出成功！")
    except IOError:
        print('文件加解密出错！！！')

def read_out_file():
    try:
        f = open('DES.txt','r',encoding = 'utf-8')
        mess = f.read()
        f.close()
        # print("文件读取成功！")
        return mess
    except IOError:
        print('文件加解密出错！！！')


#字符串转化为二进制
def str2bin(message):
    res = ""
    for i in message:  #对每个字符进行二进制转化
        tmp = bin(ord(i))[2:]  #字符转成ascii，再转成二进制，并去掉前面的0b
        for j in range(0,8-len(tmp)):   #补齐8位
            tmp = '0'+ tmp   #把输出的b给去掉
        res += tmp
    return res


#二进制转化为字符串
def bin2str(bin_str):
    res = ""
    tmp = re.findall(r'.{8}',bin_str)  #每8位表示一个字符
    for i in tmp:
        res += chr(int(i,2))  #base参数的意思，将该字符串视作2进制转化为10进制
    return res
    # print("未经过编码的加密结果:"+res)
    # print("经过base64编码:"+str(base64.b64encode(res.encode('utf-8')),'utf-8'))


#IP盒处理
def ip_change(bin_str):
    res = ""
    for i in IP_table:
        res += bin_str[i-1]     #数组下标i-1
    return res


#IP逆盒处理
def ip_re_change(bin_str):
    res = ""
    for i in IP_re_table:
        res += bin_str[i-1]
    return res

#E盒置换
def e_str(bin_str):
    res = ""
    for i in E:
        res += bin_str[i-1]
    return res


#字符串异或操作
def str_xor(my_str1,my_str2):  #str，key
    res = ""
    for i in range(0,len(my_str1)):
        xor_res = int(my_str1[i],10)^int(my_str2[i],10) #变成10进制是转化成字符串 2进制与10进制异或结果一样，都是1,0
        if xor_res == 1:
            res += '1'
        if xor_res == 0:
            res += '0'

    return res


#循环左移操作
def left_turn(my_str,num):
    left_res = my_str[num:len(my_str)]
    #left_res = my_str[0:num]+left_res
    left_res =  left_res+my_str[0:num]
    return left_res


#秘钥的PC-1置换
def change_key1(my_key):
    res = ""
    for i in PC_1:  #PC_1盒上的元素表示位置    只循环64次
        res += my_key[i-1]     #将密钥按照PC_1的位置顺序排列，
    return res

#秘钥的PC-2置换
def change_key2(my_key):
    res  = ""
    for i in PC_2:
        res += my_key[i-1]
    return res


# S盒过程
def s_box(my_str):
    res = ""
    c = 0
    for i in range(0,len(my_str),6):#步长为6   表示分6为一组
        now_str = my_str[i:i+6]    #第i个分组
        row = int(now_str[0]+now_str[5],2)   #b1b6 =r   第r行
        col = int(now_str[1:5],2)   #第c列
        #第几个s盒的第row*16+col个位置的元素
        num = bin(S[c][row*16 + col])[2:]   #利用了bin输出有可能不是4位str类型的值，所以才有下面的循环并且加上字符0
        for gz in range(0,4-len(num)):
            num = '0'+ num
        res += num
        c  += 1
    return res


#P盒置换
def p_box(bin_str):
    res = ""
    for i in  P:
        res += bin_str[i-1]
    return res



# F函数的实现
def fun_f(bin_str,key):
    first_output = e_str(bin_str)   #位选择函数将32位待加密str拓展位48位
    second_output = str_xor(first_output,key)  #将48位结果与子密钥Ki按位模2加    得到的结果分为8组（6*8）
    third_output = s_box(second_output)    #每组6位缩减位4位   S盒置换
    last_output = p_box(third_output)     #P盒换位处理  得到f函数的最终值
    return last_output


def gen_key(key):
    key_list = []
    divide_output = change_key1(key)
    key_C0 = divide_output[0:28]
    key_D0 = divide_output[28:]
    for i in SHIFT:   #shift左移位数
        key_c = left_turn(key_C0,i)
        key_d = left_turn(key_D0,i)
        key_output = change_key2(key_c + key_d)
        key_list.append(key_output)
    return key_list




def des_encrypt_one(bin_message,bin_key): #64位二进制加密的测试
    #bin_message = deal_mess(str2bin(message))
    mes_ip_bin = ip_change(bin_message)  #ip转换
    #bin_key = input_key_judge(str2bin(key))
    key_lst = gen_key(bin_key)   #生成子密钥
    mes_left = mes_ip_bin[0:32]
    mes_right = mes_ip_bin[32:]
    for i in range(0,15):
        mes_tmp = mes_right  #暂存右边32位
        f_result = fun_f(mes_tmp,key_lst[i])   #右32位与k的f函数值
        mes_right = str_xor(f_result,mes_left)  #f函数的结果与左边32位异或   作为下次右边32位
        mes_left = mes_tmp   #上一次的右边直接放到左边
    f_result = fun_f(mes_right,key_lst[15])  #第16次不用换位，故不用暂存右边
    mes_fin_left = str_xor(mes_left,f_result)
    mes_fin_right = mes_right
    fin_message = ip_re_change(mes_fin_left + mes_fin_right)   #ip的逆
    return fin_message   #返回单字符的加密结果

##64位二进制解密的测试,注意秘钥反过来了，不要写错了
def des_decrypt_one(bin_mess,bin_key):
    mes_ip_bin = ip_change(bin_mess)
    #bin_key = input_key_judge(str2bin(key))
    key_lst = gen_key(bin_key)
    lst = range(1,16)   #循环15次
    cipher_left = mes_ip_bin[0:32]
    cipher_right = mes_ip_bin[32:]
    for i in lst[::-1]:   #表示逆转列表调用
        mes_tmp = cipher_right
        cipher_right = str_xor(cipher_left,fun_f(cipher_right,key_lst[i]))
        cipher_left = mes_tmp
    fin_left = str_xor(cipher_left,fun_f(cipher_right,key_lst[0]))
    fin_right = cipher_right
    fin_output  = fin_left + fin_right
    bin_plain = ip_re_change(fin_output)
    res = bin2str(bin_plain)
    return res


#简单判断以及处理信息分组
def deal_mess(bin_mess):
    """
    :param bin_mess: 二进制的信息流
    :return: 补充的64位信息流
    """
    ans = len(bin_mess)
    if ans % 64 != 0:
        for i in range( 64 - (ans%64)):           #不够64位补充0
            bin_mess += '0'
    return bin_mess


#查看秘钥是否为64位
def input_key_judge(bin_key):
    """
    全部秘钥以补0的方式实现长度不满足64位的
    :param bin_key:
    """
    ans = len(bin_key)
    if len(bin_key) < 64:
        if ans % 64 != 0:
            for i in range(64 - (ans % 64)):  # 不够64位补充0
                bin_key += '0'
    # else:
    #     bin_key = bin_key[0:64]    #秘钥超过64位的情况默认就是应该跟密文一样长 直接将密钥变为跟明文一样的长度，虽然安全性会有所下降
    return bin_key


def all_message_encrypt(message,key):
        bin_mess = deal_mess(str2bin(message)) #得到明文的二进制比特流  64的倍数
        res = ""
        bin_key = input_key_judge(str2bin(key))   #得到密钥得二进制比特流 64的倍数
        tmp = re.findall(r'.{64}',bin_mess)    #单词加密只能实现8个字符，匹配为每64一组的列表
        for i in tmp:
            res += des_encrypt_one(i,bin_key)  #将每个字符加密后的结果再连接起来
        return res



def all_message_decrypt(message,key):
    bin_mess = deal_mess(str2bin(message))
    res = ""
    bin_key = input_key_judge(str2bin(key))
    tmp = re.findall(r'.{64}',bin_mess)
    for i in tmp:
        res += des_decrypt_one(i,bin_key)
    return res

# 获取特定的p和公钥和私钥
n = random.randint(9, 15)
print(n)
count = 64 * n
print("count:",count)
key = Key(count)  # 保存了：p,q,t,g,x,y,k,r,s的值
key.puts()  #输出所有相关的值，如公，私钥等
timesign,timeencrypt,timedecrypt=0,0,0
countacc,countfail=0,0
messageid=0
#设备1
device1=nodeInfo(nodeId='1',name='decive1',description='device1',mfgInfo=None,nodeModel='Device',modelId='1')
message_device1=device1.get_dict()
message_decive1_string = json.dumps(message_device1)
#设备2
device2=nodeInfo(nodeId='2',name='device2',description='device2',mfgInfo=None,nodeModel='Device',modelId='2')

#添加端设备1和2
print(time.time())
topoadd1=topoadd(mid=messageid,timestamp=time.time(),param=['1','2'])
message_topoadd1=topoadd1.get_dict()
message_topoadd1_string=json.dumps(message_topoadd1)
print("message is:",message_topoadd1_string)
#消息号自动+1
messageid+=1
content=message_topoadd1_string
# print("content:",content)
startsign=time.time()
list=key.sign(content)
#判断签名
is_verify=key.verif(list,content)
endsign=time.time()
print("is_verigy:",is_verify)
timesign+=endsign-startsign
print("time-sign:",endsign-startsign)
if is_verify:
    print("original message:",content.strip('\n'))
    message=content.strip('\n')
    #填充message字符
    yu=8-len(message)%8
    yustr=''
    while yu:
        yustr+=' '
        yu=yu-1
    message=message+yustr
    #密钥
    keydes=str(count)
    enstart=time.time()
    #加密
    s=all_message_encrypt(message,keydes)
    enend=time.time()
    timeencrypt+=enend-enstart
    out_mess = bin2str(s)
    print("des-encrypt:",out_mess)
    print("des-encrypt-time:",enend-enstart)
    destart=time.time()
    #解密
    s = all_message_decrypt(out_mess, keydes)
    deend=time.time()
    timedecrypt+=deend-destart
    print("des-decrypt:",s)
    print("des-decrypt-time:",deend-destart)
    #判断是否解密成功
    if s.strip(' ')==message.strip(' '):
        countacc+=1
        print("Success!")
    else:
        countfail+=1
        print("Failure!")
else:
    print("Authentication Failure")
    countfail+=1

# message_add=topoadd1.type+str(topoadd1.mid)+str(topoadd1.timestamp)+topoadd1.param
# print(message_add)
# print(topoadd1)
#with open('message.txt', 'r', encoding='utf8') as file:
    # content = file.readline()
    # while content:
    #     print("content:",content)
    #     startsign=time.time()
    #     list=key.sign(content)
    #     # print(list)
    #     is_verify=key.verif(list,content)
    #     endsign=time.time()
    #     print("is_verigy:",is_verify)
    #     timesign+=endsign-startsign
    #     print("time-sign:",endsign-startsign)
    #     if is_verify:
    #         print("original message:",content.strip('\n'))
    #         message=content.strip('\n')
    #         yu=8-len(message)%8
    #         yustr=''
    #         while yu:
    #             yustr+=' '
    #             yu=yu-1
    #         message=message+yustr
    #         keydes=str(count)
    #         enstart=time.time()
    #         s=all_message_encrypt(message,keydes)
    #         enend=time.time()
    #         timeencrypt+=enend-enstart
    #         out_mess = bin2str(s)
    #         print("des-encrypt:",out_mess)
    #         print("des-encrypt-time:",enend-enstart)
    #         destart=time.time()
    #         s = all_message_decrypt(out_mess, keydes)
    #         deend=time.time()
    #         timedecrypt+=deend-destart
    #         print("des-decrypt:",s)
    #         print("des-decrypt-time:",deend-destart)
    #         if s.strip(' ')==message.strip(' '):
    #             countacc+=1
    #             print("Success!")
    #         else:
    #             countfail+=1
    #             print("Failure")
    #     else:
    #         print("Authentication Failure")
    #         countfail+=1
    #     print()
    #     content=file.readline()
# print("message.txt-accuracy:",(countacc)/(countacc+countfail))
# print("message.txt-sign-time:",timesign)
# print("message.txt-encrypt:",timeencrypt)
# print("message.txt-decrypt:",timedecrypt)
# print("message.txt-all-time:",timesign+timeencrypt+timedecrypt)





