#!/usr/bin/env python
# -*- coding=utf8 -*-
import requests, collections, threading,threadpool, time, os, sys, logging, logging.handlers, traceback
import vistek_util.workTemplate as work_template
import requests.exceptions
import Vistek.Data as v_data
import re as RE
import psia_global_value
import eventlet
#eventlet.monkey_patch(socket=True, select=True, thread=True)
# eventlet.monkey_patch(socket=True)
try:
    import xml.etree.cElementTree as ET
except:
    import xml.etree.ElementTree as ET

try:
    import Queue
except:
    import queue as Queue

file_name = "{0}-{1}.log".format(__name__, os.getpid())
file_path = os.path.join("log", str(os.getpid()))
try:
    if not os.path.exists(file_path):
        os.makedirs(file_path)
except:
    traceback.print_exc()
log_file = os.path.join(file_path, file_name)
#log_level = logging.DEBUG
log_level = logging.INFO
logger = logging.getLogger(file_name)
handler = logging.handlers.TimedRotatingFileHandler(log_file, when="H", interval=5,backupCount=1)
formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] [%(name)s] [%(filename)s:%(funcName)s:%(lineno)s] [%(message)s]")
handler.setFormatter(formatter)
logger.addHandler(handler)
logger.setLevel(log_level)

device_info = collections.namedtuple('device_info', 'device_id ip port user pwd')

DeviceCategory=collections.namedtuple('DeviceCategory','CategoryID CategoryCode CategoryName BasicFlag')
IPTYPE=DeviceCategory(CategoryID="dc7031cb-3230-11e3-8a00-000af7160515",CategoryCode="IPC",CategoryName="网络摄像机(IPC)",BasicFlag=102)
DVRTYPE=DeviceCategory(CategoryID="59f9c9cf-3230-11e3-8a00-000af7160515",CategoryCode="DVR",CategoryName="硬盘刻录机(DVR)",BasicFlag=110)
NVRTYPE=DeviceCategory(CategoryID="dc5458f3-3230-11e3-8a00-000af7160515",CategoryCode="NVR",CategoryName="网络录像机(NVR)",BasicFlag=110)
BAYONETTYPE=DeviceCategory(CategoryID="4169188a-39a1-4ef4-9b6e-f798e292c1d1",CategoryCode="BAYNOET",CategoryName="交通卡口(Bayonet)",BasicFlag=110)
DEFAULTTYPE=DeviceCategory(CategoryID="59f9c9cf-3230-11e3-8a00-000af7160515",CategoryCode="DVR",CategoryName="硬盘刻录机(DVR)",BasicFlag=110)
DEVICE_CATEGORY={"DOME":IPTYPE,"IP CAMERA":IPTYPE,"DVR":DVRTYPE,"Network Video Recorder":NVRTYPE,"IP CAPTURE CAMERA":BAYONETTYPE,"DEFAULT":DEFAULTTYPE}
is_start = False

device_lists = dict()
device_status_lists = dict()
device_offline_count_lists = dict()#key:device_id:channel value:device_status(true or false).
status_queue = Queue.Queue()


def get_device_lists():
    global device_lists
    return device_lists


def get_device_status_lists():
    global device_status_lists
    return device_status_lists


def get_status_queue():
    global status_queue
    return status_queue


class HttpMethod():
    GET = "GET"
    PUT = "PUT"
    DEL = "DEL"
    POST = "POST"


class psia_converter():
    """
    converte the default out xml to user wanted xml.

    """

    def __init__(self, content, device=None):
        self.content = content
        ET.register_namespace('', 'urn:psialliance-org')
        self.xml_node = ET.fromstring(self.content)
        self.psia_ns = {'root_ns': 'urn:psialliance-org'}
        if device is not None:
            self.device = device

    def to_stream_url(self, device):
        stream_urls = dict()
        # channel_lists = self.xml_node.find('{urn:psialliance-org}StreamingChannelList', self.psia_ns)
        # if self.xml_node.tag != '{urn:psialliance-org}StreamingChannelList':
        #     return ''
        namespace=get_namespace(self.xml_node)
        out_streams_xml_node = ET.Element('streamurls')
        for channel in self.xml_node.iter('{0}StreamingChannel'.format(namespace)):
            # for channel in channel_lists:
            enable_node = channel.find('{0}enabled'.format(namespace))
            video_node = channel.find('{0}Video'.format(namespace))
            channel_num = int(channel.find('{0}id'.format(namespace)).text)
            transport_node = channel.find('{0}Transport'.format(namespace))
            b_support_rtsp = False
            rtsp_port_node = transport_node.find('{0}rtspPortNo'.format(namespace))
            rtsp_port = rtsp_port_node.text
            for protocol in transport_node.find('{0}ControlProtocolList'.format(namespace)):
                protocol_context_node = protocol.find('{0}streamingTransport'.format(namespace))
                if protocol_context_node is not None and protocol_context_node.text == 'RTSP':
                    b_support_rtsp = True
                    break
            if video_node is not None:
                video_enable_node = video_node.find('{0}enabled'.format(namespace))
                if enable_node is not None and enable_node.text and video_node is not None and video_enable_node.text\
                        and b_support_rtsp:
                    stream_url = 'rtsp://{0}:{1}@{2}:{3}/Streaming/Channels/{4}?transportmode={5}&profile=Profile_{' \
                                 '6}'.format(
                        device.user, device.pwd, device.ip, str(rtsp_port), str(channel_num), 'unicast',
                        str(channel_num))
                    stream_url_id = "{0}:{1}:{2}".format(device.device_id, str(channel_num), str(channel_num))  #
                    # deviceID:channleNum:streamID
                    out_stream_xml_node = ET.SubElement(out_streams_xml_node, 'stream_url')
                    out_stream_xml_node.set("id", stream_url_id)
                    out_stream_xml_node.set("user_name", str(device.user))
                    out_stream_xml_node.set("password", str(device.pwd))
                    out_streams_xml_node.set("third_party", str(False))
                    out_stream_xml_node.text = stream_url
                    if stream_url_id not in stream_urls:
                        stream_urls[stream_url_id] = stream_url
        out_streams_xml_node.set("counts", str(len(stream_urls)))
        out_streams_str = ET.tostring(out_streams_xml_node, encoding='UTF-8', method='xml')
        return out_streams_str

    def to_device_status_xml(self, device):
        # device_info_node = self.xml_node.find('root_ns:DeviceInfo', self.psia_ns)
        device_status_node = ET.Element('device_status')
        '''
        if str(self.xml_node.tag) != '{urn:psialliance-org}DeviceStatus':
            device_status_node.text = str(False)
        else:
            device_status_node.text = str(True)
        '''
        device_status_node.text = str(True)
        device_status_node.set('ip', device.ip)
        device_status_node.set('port', str(device.port))
        device_status_node.set("device_id", str(device.device_id))
        device_status_xml = ET.tostring(device_status_node, encoding='UTF-8', method='xml')
        return device_status_xml

    def std_xml(self, xml_type, device=None):
        if hasattr(self, xml_type):
            func = getattr(self, xml_type, None)
            if func is not None:
                if device is not None:
                    return func(device)
                else:
                    return func()
            else:
                return ''


class psia_uri_converter():
    def __init__(self, func_name, device):
        # self._psia_uri = self._to_psia_uri(func_name)[0]
        self._device = device
        (self._psia_uri, self._method) = self._to_psia_uri(func_name)

    def psia_uri(self):
        return self._psia_uri

    def method(self):
        return self._method

    def _to_psia_uri(self, func_name):
        if func_name == 'get_stream_url':
            return ('http://{0}:{1}/PSIA/Streaming/channels'.format(self._device.ip, self._device.port), 'GET')
        elif func_name == 'get_device_status':
            #return ('http://{0}:{1}/PSIA/System/status'.format(self._device.ip, self._device.port), 'GET')
            #由於卡口设备不支持/PSIA/System/status 先将其替换为deviceinfo
            return ('http://{0}:{1}/PSIA/System/deviceInfo'.format(self._device.ip, self._device.port), 'GET')
        elif func_name == 'get_device_info':
            return ('http://{0}:{1}/PSIA/System/deviceInfo'.format(self._device.ip, self._device.port), HttpMethod.GET)

def push_channel_status_of_offline_device(device_id,ip,port,device_channel_list):
    device_status_queue=psia_global_value.get_status_queue()
    dev_status_list_node = ET.Element("device_status_list")
    dev_status_list_node.set("dev_count", str(len(device_channel_list)))
    device_status_node = ET.Element('device_status')
    device_status_node.text = str(False)
    device_status_node.set('ip',ip)
    device_status_node.set('port', str(port))
    device_status_node.set("device_id", str(device_id))
    device_status_xml = ET.tostring(device_status_node, encoding='UTF-8', method='xml')
    device_status_queue.put(device_status_xml)

def register_device(device_id, ip, port, user_name, user_pwd,device_channel_list):
    global is_start
    #device_lists = get_device_lists()
    # device_status_lists = get_device_status_lists()
    device_lists = psia_global_value.get_device_list()
    device_status_lists = psia_global_value.get_device_status_list()
    status_queue = psia_global_value.get_status_queue()
    register_success_device_list = psia_global_value.get_register_success_device_list()
    register_fail_device_list = psia_global_value.get_register_fail_device_list()

    if device_id in device_lists:
        return ("", 0)
    register_node = ET.Element('register')
    ip_node = ET.SubElement(register_node, 'ip')
    ip_node.text = ip
    session_node = ET.SubElement(register_node, 'session')
    device_id_node = ET.SubElement(register_node, "device_id")
    device_id_node.text = str(ip)
    dev_info = device_info(device_id=device_id, ip=ip, port=port, user=user_name, pwd=user_pwd)
    url_converter = psia_uri_converter('get_device_status', dev_info)
    result = request_psia_cmd(url_converter.psia_uri(), url_converter.method(), timeout=10, auth=(user_name, user_pwd))
    if result is not None:
        if isinstance(result, unicode):
            xml_converter = psia_converter(result.encode('utf-8'))
        else:
            xml_converter = psia_converter(result)
        out_xml = xml_converter.std_xml('to_device_status_xml', dev_info)
        status_queue.put(out_xml)
        logger.info("register success id:{0} ip:{1}".format(device_id, ip))
        device_status_lists[device_id] = True
        if device_id not in register_success_device_list:
            register_success_device_list[device_id] = dev_info
    else:
        if device_id not in register_fail_device_list:
            register_fail_device_list[device_id] = dev_info
        logger.warn("register faile id:{0} ip:{1}".format(device_id, ip))
        device_status_lists[device_id] = False
        push_channel_status_of_offline_device(device_id,ip,port,device_channel_list)


    if device_id not in device_lists:
        device_lists[device_id] = device_info(device_id=device_id, ip=ip, port=port, user=user_name, pwd=user_pwd)
    register_xml = ET.tostring(register_node, encoding="UTF-8", method="xml")

    if not is_start:
        get_device_status_thrd = StartGetAllStatusThread()
        get_device_status_thrd.setName("PSIA Get All Status")
        get_device_status_thrd.start()
        get_offline_device_status_thrd = StartGetOfflineStatusThread()
        get_offline_device_status_thrd.setName("PSIA Get Offline Status")
        get_offline_device_status_thrd.start()
        check_device_status_thrd = StartCheckAllStatusThread()
        check_device_status_thrd.setName("PSIA Check All Status")
        check_device_status_thrd.start()
        is_start = True
    return (register_xml, len(register_xml))


def unregister_device(device_id):
    device_lists = psia_global_value.get_device_list()
    device_status_list = psia_global_value.get_device_status_list()
    if device_id in device_lists:
        device_lists.pop(device_id)
    if device_id in device_status_list:
        device_status_list.pop(device_id)

def request_psia_cmd(uri, method, data=None, timeout=None, auth=None):
    if auth is not None:
        request_auth = auth
    try:
        response = requests.request(method, uri, auth=request_auth, timeout=timeout)
        if response.status_code == 200:
            return response.text
        else:
            logger.error("url:{0} error code:{1} msg:{2}".format(uri, response.status_code, response.text))
            return None
    except Exception,ex:
        logger.error("exception url:{0} has except:{1}".format(uri,ex))
        return None
    # except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):  # RequestException:

def request(device_id, uri, method, timeout=None):
    #device_lists = get_device_lists()
    device_lists = psia_global_value.get_device_list()
    if timeout is None:
        timeout = 5
    if not device_lists.has_key(device_id):
        return None
    else:
        login_info = device_lists.get(device_id)
        request_auth = (login_info.user, login_info.pwd)
        try:
            response = requests.request(method, uri, auth=request_auth, timeout=timeout)
            if response.status_code == 200:
                return response.text
            else:
                logger.warn("request url:{0} warn text:{1} error_code:{2}".format(uri, response.text, response.status_code))
                return None
        except requests.exceptions.RequestException:
            logger.error("exception dev_id:{0} ip:{1} exception:{2}".format(device_id, login_info.ip, traceback.format_exc()))

            return None

        # except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError):  # RequestException:
        #     return None

def get_stream_url(device_id, channel=None):
    #device_lists = get_device_lists()
    device_lists = psia_global_value.get_device_list()
    if not device_lists.has_key(device_id):
        return ('', 0)
    # login_info = device_info._make(list(device_lists.get(device_id)))
    login_info = device_lists.get(device_id)
    tmp_psia_uri = psia_uri_converter('get_stream_url', login_info)
    tmp_out_data = request(device_id, tmp_psia_uri.psia_uri(), tmp_psia_uri.method())
    if tmp_out_data is None:
        logger.error(
            "get_stream_url failed psia_uri:{0}, device_id:{1}".format(tmp_psia_uri.psia_uri(), str(device_id)))
        return ('', 0)
    else:
        if isinstance(tmp_out_data, unicode):
            xml_converter = psia_converter(tmp_out_data.encode('utf-8'))
        else:
            xml_converter = psia_converter(tmp_out_data)
        # login_info = device_info._make(list(device_lists.get(device_id)))
        login_info = device_lists.get(device_id)
        out_xml = xml_converter.std_xml('to_stream_url', login_info)
        logger.debug("get_stream_url success psia_uri:{0}, out_xml:{1}".format(tmp_psia_uri.psia_uri(), str(out_xml)))
        return (out_xml, len(out_xml))

def get_device_status_by_eventlet(device_info):
    if device_info is not None:
        tmp_psia_uri = psia_uri_converter('get_device_status', device_info)
        auth = (device_info.user, device_info.pwd)
        tmp_out_data = request_psia_cmd(tmp_psia_uri.psia_uri(), tmp_psia_uri.method(), timeout=10, auth=auth)
        if tmp_out_data is None:
            return ("", 0)
        else:
            xml_converter_result = psia_converter(tmp_out_data, device_info)
            out_xml = xml_converter_result.std_xml('to_device_status_xml', device_info)
            return (out_xml, len(out_xml))

def get_device_status(device_id):
    #device_lists = get_device_lists()
    device_lists = psia_global_value.get_device_list()
    offline_device_lists = psia_global_value.get_offline_device_lists()
    if not device_lists.has_key(device_id):
        logger.warn("device not exist, id:", device_id)
        return ("", 0)
    login_info = device_lists.get(device_id)
    tmp_psia_uri = psia_uri_converter('get_device_status', login_info)
    try:
        tmp_out_data = request(device_id, tmp_psia_uri.psia_uri(), tmp_psia_uri.method(), timeout=5)
        if tmp_out_data is None:
            device_status_node = ET.Element('device_status')
            device_status_node.text = str(False)
            device_status_node.set('ip', login_info.ip)
            device_status_node.set('port', str(login_info.port))
            device_status_node.set("device_id", str(login_info.device_id))
            device_status_xml = ET.tostring(device_status_node, encoding='UTF-8', method='xml')
            logger.info("device_stats:{0}".format(out_xml))
            return (device_status_xml, len(device_status_xml))
        else:
            xml_converter_result = psia_converter(tmp_out_data, login_info)
            out_xml = xml_converter_result.std_xml('to_device_status_xml', login_info)
            if device_id in offline_device_lists:
                offline_device_lists.remove(device_id)
            # print("get-status end time:", time.asctime(time.localtime(time.time())))
            logger.info("device_stats:{0}".format(out_xml))
            return (out_xml, len(out_xml))
    except Exception,ex:
        device_status_node = ET.Element('device_status')
        device_status_node.text = str(False)
        device_status_node.set('ip', login_info.ip)
        device_status_node.set('port', str(login_info.port))
        device_status_node.set("device_id", str(login_info.device_id))
        device_status_xml = ET.tostring(device_status_node, encoding='UTF-8', method='xml')
        offline_device_lists.add(device_id)
        logger.error("Get device status Excepton ip:{0},device_id:{1},Ex:{2}".format(login_info.ip,login_info.device_id,ex))
        return (device_status_xml, len(device_status_xml))



def start_device_status_service():
    if not is_start:
        t = StartServerThread()
        t.start()


def add_device_category(device,device_name):
    if device.DeviceCategory is None:
        device.DeviceCategory=v_data.DmDeviceCategory()
    for key,value in DEVICE_CATEGORY.items():
        print(key)
        print(device_name)
        if key in device_name:
            device.DeviceCategory.CategoryID=value.CategoryID
            device.DeviceCategory.CategoryCode=value.CategoryCode
            device.DeviceCategory.CategoryName=value.CategoryName
            device.DeviceCategory.BasicFlag=value.BasicFlag
            return
    device.DeviceCategory.CategoryID = DEVICE_CATEGORY["DEFAULT"].CategoryID
    device.DeviceCategory.CategoryCode = DEVICE_CATEGORY["DEFAULT"].CategoryCode
    device.DeviceCategory.CategoryName = DEVICE_CATEGORY["DEFAULT"].CategoryName
    device.DeviceCategory.BasicFlag = DEVICE_CATEGORY["DEFAULT"].BasicFlag

def get_device_Manufacture(DeviceInfoXML):
    if 'hik' in DeviceInfoXML or 'Hikvision' in DeviceInfoXML or 'hikvision' in DeviceInfoXML :
        return "hikvision"
    if 'dahua' in DeviceInfoXML or "Dahua" in DeviceInfoXML:
        return "dahua"
    if 'topzen' in DeviceInfoXML or "Topzen" in DeviceInfoXML:
        return "topzen"
    return "onvif_support"

def get_namespace(element):
    m = RE.match('\{.*\}', element.tag)
    return m.group(0) if m else ''

def try_get_device_info(device, timeout=None):
    if device:
        ip = device.IP
        port = device.Port
        user_name = device.Username
        password = device.Password
        get_device_info_uri = "http://{0}:{1}/PSIA/System/deviceInfo".format(ip, port)
        get_device_video_channels_uri = "http://{0}:{1}/PSIA/System/Video/inputs/channels".format(ip, port)
        if not timeout:
            timeout = 5
        request_auth = (user_name, password)
        try:
            response = requests.request(HttpMethod.GET, get_device_info_uri, auth=request_auth, timeout=timeout)
            video_out_data = requests.request(HttpMethod.GET, get_device_video_channels_uri, auth=request_auth,\
                                              timeout=timeout)
            if response:
                if isinstance(response.text, unicode):
                    device_info_node = ET.fromstring(response.text.encode("utf-8"))
                    response_text=response.text.encode("utf-8")
                else:
                    device_info_node = ET.fromstring(response.text)
                namespace=get_namespace(device_info_node)
                if device_info_node is not None:
                    syscontact_node = device_info_node.find("{0}systemContact".format(namespace))
                    if syscontact_node is not None:#IPC
                        device.Manufacture = get_device_Manufacture(syscontact_node.text)
                    else:#DVR OR NVR
                        device.Manufacture=get_device_Manufacture(response_text)
                    device_name=device_info_node.find("{0}deviceName".format(namespace))
                    add_device_category(device,str(device_name.text))

            if video_out_data:
                if isinstance(video_out_data.text, unicode):
                    root_node = ET.fromstring(video_out_data.text.encode("utf-8"))
                else:
                    root_node = ET.fromstring(video_out_data.text.encode("utf-8"))

                channel_list = []
                namespace=get_namespace(root_node)
                for item in root_node.iter("{0}VideoInputChannel".format(namespace)):
                    v_channel = v_data.DmDeviceVideoChannel()
                    id_node = item.find("{0}id".format(namespace))
                    if device.DeviceID:
                        v_channel.DeviceID = device.DeviceID
                    if id_node is not None:
                        v_channel.Name = "{0}-{1}".format(device.IP, int(id_node.text)-1)
                        v_channel.ChannelIndex = int(id_node.text)-1
                    else:
                        print("id_node is none.")
                    channel_list.append(v_channel)
                if not device.ChannelList:
                    device.ChannelList = channel_list
            if response.status_code == 200:
                logger.info("try device success id:{0} ip:{1} pid:{2} threadid:{3}.".format(device.DeviceID \
                                                                                            , device.IP \
                                                                                            , os.getpid() \
                                                                                            , threading.currentThread().ident))
                # logger.info("try process device success, device:{0}".format(device))
                device.ProtocolFlag = 4
                return (device.DeviceID, True, 4, None)
            else:
                logger.error("try device id:{0} ip:{1} pid:{2} threadid:{3} exception fail!!!".format(device.DeviceID \
                                                                                                      , device.IP \
                                                                                                      , os.getpid() \
                                                                                                      , threading.currentThread().ident))
                
                return (device.DeviceID, False, 0, None)
        # except (requests.exceptions.ConnectTimeout, requests.exceptions.ConnectionError, Exception):  # RequestException:
        #     logger.error("try device id:{0} ip:{1} pid:{2} threadid:{3} exception fail!!!".format(device.DeviceID \
        #                                                                                           , device.IP \
        #                                                                                           , os.getpid() \
        #                                                                                           , threading.currentThread().ident))
        except Exception,ex:  # RequestException:
            logger.error("try device id:{0} ip:{1} pid:{2} threadid:{3} exception fail:{4}!!!".format(device.DeviceID \
                                                                                              , device.IP \
                                                                                              , os.getpid() \
                                                                                              ,threading.currentThread().ident \
                                                                                              ,ex))
            return (device.DeviceID, False, 0, None)
def get_all_status_callback(request,result):
    all_status_queue = psia_global_value.get_all_status_queue()
    logger.info("get status:{0}".format(result[0]))
    all_status_queue.put([result[0]])
def start_get_all_status():
    device_list = psia_global_value.get_device_list()
    all_status_queue = psia_global_value.get_all_status_queue()
    task_pool = eventlet.GreenPool(size=5000)
    is_stop_event = psia_global_value.get_is_stop_event()
    while 1:
        if 0 < len(device_list):
            device_id_list = device_list.keys()
            device_info_list = device_list.values()
            begin_time = time.time()
            #result = task_pool.imap(get_device_status, device_info_list)
            result = task_pool.imap(get_device_status, device_id_list)
            #result = task_pool.imap(get_device_status_by_eventlet, device_info_list)
            task_pool.waitall()
            if result is not None:
                all_status_queue.put([item[0] for item in result])
            end_time = time.time()
            logger.debug("get all status time:{0} device count:{1}".format((end_time-begin_time), len(device_id_list)))
        if is_stop_event.is_set():
            break
        is_stop_event.wait(5)
def start_get_all_status_by_threadpool():
    device_list = psia_global_value.get_device_list()
    all_status_queue = psia_global_value.get_all_status_queue()
    offline_device_list = psia_global_value.get_offline_device_lists()

    task_pool = threadpool.ThreadPool(32)
    is_stop_event = psia_global_value.get_is_stop_event()
    while 1:
        if 0 < len(device_list):
            device_id_list = device_list.keys()
            device_info_list = device_list.values()
            begin_time = time.time()
            requests=[]
            for device in device_id_list:
                if device not in offline_device_list:
                    requests.extend(threadpool.makeRequests(get_device_status,[((device, ), {})],get_all_status_callback))
            map(task_pool.putRequest,requests)
            task_pool.wait()
            del requests
            end_time = time.time()
            logger.info("get all status time:{0} device count:{1}".format((end_time-begin_time), len(device_id_list)))
        if is_stop_event.is_set():
            break
        is_stop_event.wait(5)

def start_get_offline_status_by_threadpool():
    device_list = psia_global_value.get_device_list()
    all_status_queue = psia_global_value.get_all_status_queue()
    offline_device_list = psia_global_value.get_offline_device_lists()

    task_pool = threadpool.ThreadPool(8)
    is_stop_event = psia_global_value.get_is_stop_event()
    while 1:
        logger.info("length of offline_device_list:{0}".format(len(offline_device_list)))
        if 0 < len(offline_device_list):
            begin_time = time.time()
            requests=[]
            for device in offline_device_list:
                requests.extend(threadpool.makeRequests(get_device_status,[((device, ), {})],get_all_status_callback))
            map(task_pool.putRequest,requests)
            task_pool.wait()
            del requests
            end_time = time.time()
            logger.info("get all status time:{0} device count:{1}".format((end_time-begin_time), len(offline_device_list)))
        if is_stop_event.is_set():
            break
        is_stop_event.wait(1)
class StartGetAllStatusThread(threading.Thread):
    def run(self):
        start_get_all_status_by_threadpool()
class StartGetOfflineStatusThread(threading.Thread):
    def run(self):
        start_get_offline_status_by_threadpool()
def start_check_all_staus():
    device_status_manager = work_template.WorkerManager(16, 2)
    while True:
        device_lists = get_device_lists()
        device_status_lists = get_device_status_lists()
        for device_id, login_info in device_lists.items():
            device_status_manager.add_job(get_device_status, login_info.device_id)
        device_status_manager.wait_for_complete()
        out_queue = get_status_queue()
        while not device_status_manager.result_queue_empty():
            out_str = device_status_manager.get_result()
            if 1 > len(out_str[0]):
                continue
            device_status_node = ET.fromstring(out_str[0])
            dev_node_id = device_status_node.get('device_id')
            if device_status_lists.has_key(dev_node_id) and device_status_node.text != str(
                    device_status_lists.get(dev_node_id)):
                logger.info(time.asctime(time.localtime(time.time())), 'status_change:', out_str)
                out_queue.put(out_str)
        time.sleep(5)

def start_check_all_status_by_eventlet():
    all_status_queue = psia_global_value.get_all_status_queue()
    is_stop_event = psia_global_value.get_is_stop_event()
   # task_pool = eventlet.GreenPool()
    while 1:
        if is_stop_event.is_set():
            break
        while not all_status_queue.empty():
            status_list = all_status_queue.get()
            map(do_check_device_status, status_list)
            #result = task_pool.starmap(do_check_device_status, status_list)
            #result = task_pool.imap(do_check_device_status, status_list)
        #task_pool.waitall()
        is_stop_event.wait(0.01)

def do_check_device_status(status_xml):
    device_status_list = psia_global_value.get_device_status_list()
    status_queue = psia_global_value.get_status_queue()
    off_device_status_list = psia_global_value.get_off_device_status_count_list()
    if status_xml is not None and 0 < len(status_xml):
        logger.info("check device status:{0}".format(status_xml))
        root_node = ET.fromstring(status_xml)
        dev_id = root_node.get("device_id")
        if dev_id in device_status_list:
            if str(root_node.text) != str(device_status_list.get(dev_id)):
                logger.info("status change:{0}".format(status_xml))
                # once on line one time report it.
                if str(root_node.text).lower() == "true":
                    device_status_list[dev_id] = True
                    status_queue.put(status_xml)
                    return
                # once offline check two times 如果下线则，检测三次
                if dev_id in off_device_status_list:
                    if 1 < off_device_status_list.get(dev_id):
                        status_queue.put(status_xml)
                        if str(root_node.text).lower() == "false":
                            device_status_list[dev_id] = False
                        else:
                            device_status_list[dev_id] = True
                        off_device_status_list[dev_id] = 0
                    else:
                        off_device_status_list[dev_id] += 1
                else:
                    off_device_status_list[dev_id] = 1
            else:
                off_device_status_list[dev_id] = 0
                # status_queue.put(status_xml)
                # if root_node.text == "True":
                #     device_status_list[dev_id] = True
                # else:
                #     device_status_list[dev_id] = False
        else:
            logger.error("deviceid:{0} not in device status list".format(dev_id))


class StartCheckAllStatusThread(threading.Thread):
    def run(self):
        #start_check_all_staus()
        start_check_all_status_by_eventlet()

class StartServerThread(threading.Thread):
    def run(self):
        start_check_all_staus()


if __name__ == '__main__':

    dev_id = 10

    # for item in xrange(3):
    #register_device(str(dev_id), '172.16.1.198', 80, 'admin', 'admin123',[])
    #get_stream_url(str(dev_id))
    #     dev_id +=1

    # out = get_stream_url('111')
    # print('out:', out, 'len:', len(out), 'type:', type(out))
    # out = get_device_status('111')
    # print('out:', out, 'len:', len(out), 'type:', type(out))
    # device = v_data.DmDevice()
    # device.IP = "172.16.1.194"
    # device.Port = 80
    # device.Username = "admin"
    # device.Password = "vistek123456"
    # try_get_device_info(device, timeout=2)
    '''
    status_queue = psia_global_value.get_status_queue()
    while 1:
        if not status_queue.empty():
            print("status change:{0}".format(status_queue.get()))
        time.sleep(10)

    '''
    device = v_data.DmDevice()
    device.IP = "172.16.1.198"
    device.Port = 80
    device.Username = "admin"
    device.Password = "admin123"
    try_get_device_info(device)
    print(device)

