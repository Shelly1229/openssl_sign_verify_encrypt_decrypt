class nodeInfo(object):
    def __init__(self,nodeId=None,name=None,description=None,mfgInfo=None,nodeModel=None,modelId=None) -> None:
        self.nodeId=nodeId #端设备唯一标识
        self.name=name #端设备名称
        self.description=description #端设备描述
        self.mfgInfo=mfgInfo #端设备厂商信息
        self.nodeModel=nodeModel #端设备型号
        self.modelId=modelId #端设备模型编号（非必选）
    def get_nodeid(self):
        return self.nodeId
    def set_nodeid(self,nodeid):
        self.nodeId=nodeid
    def get_name(self):
        return self.name
    def set_name(self,name):
        self.name=name
    def get_description(self):
        return self.description
    def set_description(self,description):
        self.description=description
    def get_mfginfo(self):
        return self.mfgInfo
    def set_mfginfo(self,mfginfo):
        self.mfgInfo=mfginfo
    def get_nodemodel(self):
        return self.nodeModel
    def set_nodemodel(self,nodemodel):
        self.nodeModel=nodemodel
    def get_modelid(self):
        return self.modelId
    def set_modelid(self,modelid):
        self.modelId=modelid
    def get_dict(self):
        return {'nodeid':self.nodeId,
                'name':self.name,
                'description':self.description,
                'mfginfo':self.mfgInfo,
                'nodemodel':self.nodeModel,
                'modelid':self.modelId}
    
class topoadd(object):
    def __init__(self,type='CMD_TOPO_ADD',mid=None,timestamp=None,expire=-1,param=None) -> None:
        self.type=type #端设备添加报文
        self.mid=mid #该消息的编号，自主生成
        self.timestamp=timestamp #毫秒精度，根据当前时间生成
        self.expire=expire#默认为-1，表示永不过期 
        self.param=param #端设备信息列表，列表大小1-100
    def get_dict(self):
        return {'type':self.type,
                'mid':self.mid,
                'timestamp':self.timestamp,
                'expire':self.expire,
                'param':self.param}
    

class topodel(object):
    def __init__(self,type='CMD_TOPO_DEL',mid=0,timestamp=None,param=None) -> None:
        self.type=type #端设备添加报文
        self.mid=mid #该消息的编号，自主生成
        self.timestamp=timestamp #毫秒精度，根据当前时间生成 
        self.param=param #端设备信息列表，列表大小1-100

class nodeStatuses(object):
    def __init__(self,deviceId=None,status=None) -> None:
        self.deviceId=deviceId #平台生成的端设备唯一标识
        self.status=status #OFFLINE设备离线 ONLINE设备上线
    def get_status(self):
        return self.status
    def set_deviceid(self,deviceId):
        self.deviceId=deviceId
    def set_status(self,status):
        self.status=status
        
class topoupdate(object):
    def __init__(self) -> None:
        self.type='CMD_TOPO_UPDATE' #端设备添加报文
        self.mid=0 #该消息的编号，自主生成
        self.timestamp=0 #毫秒精度，根据当前时间生成 
        self.param= None #端设备信息列表，列表大小1-100


