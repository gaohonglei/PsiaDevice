#!/usr/bin/env python
# -*- coding=utf-8 -*-

import time, inspect
import psia_global_value

try:
    import psia_wrap
except:
    from . import psia_wrap
from urlobject import URLObject

import psia_global_value
class uri_parser():
    """uri parser"""

    def __init__(self, uri):
        """init function"""
        self._uri = URLObject(uri)
        self._params = self._uri.query.dict
        self._func_name = ''
        self._psia_uri = self.__psia_uri__()

    def __psia_uri__(self):
        if self.func_name('func') == 'get_stream_url':
            return 'http://{0}:{1}/PSIA/Streaming/channels'.format(self.ip, self.port)
        else:
            return ''

    @property
    def user_name(self):
        return self._uri.username

    @property
    def password(self):
        return self._uri.password

    @property
    def ip(self):
        return self._uri.hostname

    @property
    def port(self):
        return self._uri.port

    def add_func_param(self, param):
        self._params.update(param)

    #@property
    def func_name(self, name):
        if name in self._params:
            self._func_name = self._params[name]
            return self._func_name
        else:
            return ''

    def func_params(self, name):
        if name in self._params and self._params[name] == 'register_device':
            self.add_func_param({'ip': self._uri.hostname})
            self.add_func_param({'port': self._uri.port})
            self.add_func_param({'user_name': self._uri.username})
            self.add_func_param({'user_pwd': self._uri.password})
        if name in self._params:
            self._params.pop(name)
        return self._params


def getStatusQueue():
    return psia_global_value.get_status_queue()


def try_process_device(device):
    func = getattr(psia_wrap, "try_get_device_info")
    if func:
        #out_data = func(device.DeviceID, device.IP, device.Port, device.Username, device.Password)
        out_data = func(device, timeout=5)
        return out_data
    else:
        return None


def request_cmd(device_id, uri, params):
    """device cmd"""
    func_lists = dir(psia_wrap)
    parser = uri_parser(uri)
    parser.add_func_param({'device_id': device_id})
    func_name_flag = "func"
    func_name = parser.func_name(func_name_flag)
    if func_name in func_lists:
        cmd_func = getattr(psia_wrap, func_name)
        cmd_params = parser.func_params(func_name_flag)
        # print('begin device_id:', device_id, 'uri:', uri, 'params:', params, 'cmdname:', func_name, 'cmd:',
        # cmd_func, 'func_param:', parser.func_params('func'))
        params_lists = []
        need_args = inspect.getargspec(cmd_func).args
        for call_args in need_args:
            if cmd_params.has_key(call_args):
                params_lists.append(cmd_params.get(call_args))
        if func_name=='register_device':
            out_data = cmd_func(device_channel_list=params,**cmd_params)
        else:
            out_data=cmd_func(**cmd_params)
        # print("end out_data:", out_data, "type:", type(out_data))
        return out_data

def getCurrentDeviceInfo():
    return psia_global_value.get_current_device_info()


if __name__ == '__main__':
    out = request_cmd('172.16.1.191', 'http://admin:12345@172.16.1.191:80/device?func=register_device', '')
    for item in range(5):
        out = request_cmd('172.16.1.191', 'http://172.16.1.191:80/device/meida?func=get_stream_url', '')
        out = request_cmd('172.16.1.191', 'http://172.16.1.191:80/device?func=get_device_status', '')
        time.sleep(5)
    raw_input()
