#!/usr/bin/env python
# -*- coding=utf-8 -*-

"""
@version: 0.0.1
@author: lee
@license: Apache Licence
@contact: shida23577@hotmail.com
@software: PyCharm Community Edition
@file: psia_global_value.py
@time: 2016/6/14 10:19
"""
__title__ = ''
__version = ''
__build__ = 0x000
__author__ = 'lee'
__license__ = 'Apache 2.0'
__copyright__ = 'Copyright 2016 li shi da'


import threading
try:
    import Queue
except:
    import queue as Queue

device_list = {}
def get_device_list():
    global device_list
    return device_list

device_status_list = {}
def get_device_status_list():
    global device_status_list
    return device_status_list

off_device_status_count_list = {}#device_id:channel status example {xxxx:1 :False}
def get_off_device_status_count_list():
    global off_device_status_count_list
    return off_device_status_count_list

offline_device_lists = set()#注册的设备列表 {"device_id":login_session(namedtuple)}
def get_offline_device_lists():
    global offline_device_lists
    return offline_device_lists

status_queue = Queue.Queue()
def get_status_queue():
    global status_queue
    return status_queue

all_status_queue = Queue.Queue()
def get_all_status_queue():
    return all_status_queue

is_stop_event = threading.Event()
def get_is_stop_event():
    global is_stop_event
    return is_stop_event

register_success_device_list = {}
def get_register_success_device_list():
    global register_success_device_list
    return register_success_device_list

register_fail_device_list = {}
def get_register_fail_device_list():
    global register_fail_device_list
    return register_fail_device_list

def get_current_device_info():
    device_list = get_device_list()
    register_success_device_list = get_register_success_device_list()
    register_fail_device_list = get_register_fail_device_list()
    success_count = len(register_success_device_list)
    fail_count = len(register_fail_device_list)
    register_success_device_id_list = list((item.device_id) for item in register_success_device_list.values())
    if 0 < len(register_success_device_list):
        register_success_str = ":".join(register_success_device_id_list)
    else:
        register_success_str = ""
    register_fail_device_id_list = list((item.device_id) for item in register_fail_device_list.values())
    if 0 < len(register_fail_device_id_list):
        register_fail_str = ":".join(register_fail_device_id_list)
    else:
        register_fail_str = ""
    return (len(device_list), success_count, fail_count, register_success_str, register_fail_str)
