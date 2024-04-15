import json

message_all=['topoadd.json',"topodel.json","topoupdate.json"]
for file_name in message_all:
    print("open:",file_name)
    with open(file_name,'r',encoding='utf-8') as files:
        data=json.load(files)
        print(data)

    print()

# import json

# # 打开JSON文件列表
# with open('test.jsonlist', 'r') as file:
#     # 逐行读取文件内容
#     for line in file:
#         # 解析每行内容为JSON对象
#         data = json.loads(line)
#         print(data)

# 输出：
# {'name': 'John', 'age': 25, 'city': 'New York'}
# {'name': 'Alice', 'age': 30, 'city': 'San Francisco'}
# {'name': 'Bob', 'age': 35, 'city': 'Chicago'}