#!/usr/bin/env python
#coding:utf-8

import os
import shutil
import pcap_analysis
import re
from xml.dom.minidom import Document
import hashlib

def create_http_xml(filename):
    http_file = open(filename,'rb')
    http_data_string = http_file.read()
    print_xml_file(http_data_string)
    http_file.close()

def write_file(string):
    m = hashlib.md5()
    m.update(string)
    file_name = m.hexdigest()
    content_filename = file_name + '.txt'
    f = open(content_filename,'wb')
    f.write(string)
    f.close()
    shutil.copy(content_filename,content_path)
    os.remove(content_filename)
    return file_name

def print_xml_file(string):
    global content_filename
    if len(string) > 0:
        request = doc.createElement('Request')
        http.appendChild(request)
        #对request部分进行处理
        #得到Method的值
        head_offset = string.find('\r\n\r\n')
        head = string[0:head_offset]
        method_offset = head.find(' ')
        method = head[0:method_offset]
        create_xml(request,'Method',method)
        #得到Method后的部分路径值
        path_behind_offset = head[method_offset+1:].find(' ')
        path_behind = head[method_offset+1:method_offset+1+path_behind_offset]
        #得到Host的值
        host_offset = head.find('Host:')
        if host_offset < 0:
            host_offset = head.find('host: ')
        # print head[0:host_offset]
        # print host_offset
        host_enter_offset = head[host_offset+6:].find('\r\n')
        if host_enter_offset > 0:
            host = head[host_offset+6:host_offset+6+host_enter_offset]
        else:
            host = head[host_offset+6:]
        create_xml(request,'Host',host)
        #得到Path的值
        path = host + path_behind
        create_xml(request,'Path',path)
        # print host,path
        #如果方法是Post的讨论
        if method == 'POST':
            #得到Content-Length的值
            head_content_offset = head.find('Content-Length: ')
            head_content_enter_offset = head[head_content_offset+16:].find('\r\n')
            if head_content_enter_offset > 0:
                head_content_length = head[head_content_offset+16:head_content_offset+16+head_content_enter_offset]
            else:
                head_content_flag = re.compile('Content-Length: (.\d*)')
                head_content_length = head_content_flag.findall(head)[0]
                head_content_length = int(head_content_length)
            head_content = string[head_offset+4:head_offset+4+int(head_content_length)]
            if head_content[0:4] != 'POST':
                content_file = write_file(head_content)
                head_content_path = content_path + content_file
                create_xml(request,'Content',head_content_path)
                boundary_offset = head.find('boundary=')
                if boundary_offset > 0:
                    filename_flag = re.compile('filename="(.*?)"')
                    filename = filename_flag.findall(head_content)[0]
                    if len(filename) > 0:
                        create_xml(request,'filename',filename)
                #处理response部分
                response = doc.createElement('Response')
                http.appendChild(response)
                response_head_offset = string[head_offset+4+int(head_content_length):].find('\r\n\r\n')
                response_head = string[head_offset+4+int(head_content_length):head_offset+4+int(head_content_length)+response_head_offset]
                #得到status_line的值
                status_enter_offset = response_head.find('\r\n')
                status_line = response_head[0:status_enter_offset]
                if len(status_line) > 0:
                    http_offset = status_line.find('HTTP')
                    if http_offset >= 0:
                        status_line = status_line[http_offset:]
                        create_xml(response,'Status_line',status_line)
                Content_Length_offset = response_head.find('Content-Length: ')
                Transfer_Encoding_offset = response_head.find('Transfer-Encoding: chunked')
                if Content_Length_offset > 0:
                    content_length_enter = response_head[Content_Length_offset+16:].find('\r\n')
                    response_content_length = response_head[Content_Length_offset+16:Content_Length_offset+16+content_length_enter]
                    content = string[head_offset+4+int(head_content_length)+response_head_offset+4:head_offset+4+int(head_content_length)+response_head_offset+4+int(response_content_length)]
                    request_length_content_file = write_file(content)
                    request_length_content_path = content_path + request_length_content_file
                    create_xml(response,'Content',request_length_content_path)
                    string = string[head_offset+4+int(head_content_length)+response_head_offset+4+int(response_content_length):]
                    print_xml_file(string)
                elif Transfer_Encoding_offset > 0:
                    content_chunked_offset = string[head_offset+4+int(head_content_length)+response_head_offset+4:].find('\r\n\r\n')
                    content_chunked = string[head_offset+4+int(head_content_length)+response_head_offset+4:head_offset+4+int(head_content_length)+response_head_offset+4+content_chunked_offset]
                    request_chunck_content_file = write_file(content_chunked)
                    request_chunck_content_path = content_path + request_chunck_content_file
                    create_xml(response,'Content',request_chunck_content_path)
                    string = string[head_offset+4+int(head_content_length)+response_head_offset+4+content_chunked_offset+4:]
                    print_xml_file(string)
            else:
                boundary_offset = head.find('boundary=')
                if boundary_offset > 0:
                    filename_flag = re.compile('filename="(.*?)"')
                    filename = filename_flag.findall(head_content)[0]
                    if len(filename) > 0:
                        create_xml(request,'filename',filename)
        # #是否有boundary
        # boundary_offset = head.find('boundary')
        # if boundary_offset > 0:
        #     boundary_enter = head[boundary_offset+9:].find('\r\n')
        #     boundary = head[boundary_offset+9:boundary_offset+9+boundary_enter]
        #     content_length_offset = re.compile('Content-Length: \d*')
        #     head_content_length_all = content_length_offset.findall(head)[0]
        #     head_content_length = head_content_length_all[16:]
        else:
            #处理response部分
            response = doc.createElement('Response')
            http.appendChild(response)
            response_head_offset = string[head_offset+4:].find('\r\n\r\n')
            response_head = string[head_offset+4:head_offset+4+response_head_offset]
            #得到status_line的值
            status_enter_offset = response_head.find('\r\n')
            status_line = response_head[0:status_enter_offset]
            if len(status_line) > 0:
                http_offset = status_line.find('HTTP')
                if http_offset >= 0:
                    status_line = status_line[http_offset:]
                    create_xml(response,'Status_line',status_line)
            Content_Length_offset = response_head.find('Content-Length: ')
            Transfer_Encoding_offset = response_head.find('Transfer-Encoding: chunked')
            if Content_Length_offset > 0:
                content_length_enter = response_head[Content_Length_offset+16:].find('\r\n')
                if content_length_enter > 0:
                    response_content_length = response_head[Content_Length_offset+16:Content_Length_offset+16+content_length_enter]
                else:
                    content_length_flag = re.compile('Content-Length: (.\d*)')
                    response_content_length = content_length_flag.findall(response_head)[0]
                    response_content_length = int(response_content_length)
                content = string[head_offset+4+response_head_offset+4:head_offset+4+response_head_offset+4+int(response_content_length)]
                response_length_content_file = write_file(content)
                response_length_content_path = content_path + response_length_content_file
                create_xml(response,'Content',response_length_content_path)
                string = string[head_offset+4+response_head_offset+4+int(response_content_length):]
                print_xml_file(string)
            elif Transfer_Encoding_offset > 0:
                content_chunked_offset = string[head_offset+4+response_head_offset+4:].find('\r\n\r\n')
                content_chunked = string[head_offset+4+response_head_offset+4:head_offset+4+response_head_offset+4+content_chunked_offset]
                response_chunck_content_file = write_file(content_chunked)
                response_chunck_content_path = content_path + response_chunck_content_file
                create_xml(response,'Content',response_chunck_content_path)
                string = string[head_offset+4+response_head_offset+4+content_chunked_offset+4:]
                print_xml_file(string)

def create_xml(parent,child_element,child_value):
    child = doc.createElement(child_element)
    child_text = doc.createTextNode(child_value)
    child.appendChild(child_text)
    parent.appendChild(child)

#目录文件定义
pcap_filename = pcap_analysis.pcapfile
result_path = 'result/' + pcap_filename + '/'
file_path = 'result/' + pcap_filename + '/' + 'http/'
content_path = 'result/' + pcap_filename + '/' + 'http/http_content/'

#文件存在则覆盖
if os.path.exists(file_path):
    shutil.rmtree(file_path)
    os.makedirs(file_path)
else:
    os.makedirs(file_path)

if os.path.exists(content_path):
    shutil.rmtree(content_path)
    os.makedirs(content_path)
else:
    os.makedirs(content_path)

#调用pcap_analysis.py文件夹中的request_port_assist列表
conversation_port_list = pcap_analysis.request_port_assist

#读取处理请求和相应的报文数据
finaldata_request = open('request.txt','rb')
string_request = finaldata_request.read()
request = string_request

finaldata_response = open('response.txt','rb')
string_response = finaldata_response.read()
response = string_response
#i标记每个会话的顺序，一个会话写入一个result.txt文本文件中
i = 1

#创建DOM文档对象
doc = Document()

#创建根元素
http = doc.createElement('HTTP')
#设置命名空间
http.setAttribute('xmlns:xsi',"http://www.w3.org/2001/XMLSchema-instance")
#引用本地XML Schema
http.setAttribute('xsi:noNamespaceSchemaLocation','result.xsd')
doc.appendChild(http)

while len(request) > 0 and len(response) > 0:
    conversation_filename = 'result' + str(i) + '  PortA:' + str(conversation_port_list[i-1]) +'.txt'
    conversation_data = open(conversation_filename,'wb')
    #以======分割不同的会话
    request_conversation_offset = request.find('=====')
    request_conversation_data = request[0:request_conversation_offset]
    response_conversation_offset = response.find('=====')
    if response_conversation_offset == 0:
        response_conversation_offset = response[6:].find('=====')
        response_conversation_data = response[6:response_conversation_offset]
    else:
        response_conversation_data = response[0:response_conversation_offset]
    #对每个会话的结束进行判断
    while len(request_conversation_data) > 0:
        #request处理
        #request以空行分割
        request_enter_offset = request_conversation_data.find('\r\n\r\n')
        if request_enter_offset > 0:
            request_contentlength = request_conversation_data[0:request_enter_offset].find('Content-Length: ')
            if request_contentlength > 0:
                request_contentlength_enter = request_conversation_data[request_contentlength:].find('\r\n')
                request_content_length = request_conversation_data[request_contentlength+16:request_contentlength+request_contentlength_enter]
                request_data = request_conversation_data[0:request_enter_offset+4+int(request_content_length)]
                if len(request_data) < request_enter_offset+4+int(request_content_length):
                    conversation_data.write(request_conversation_data[0:request_enter_offset+4])
                    request_conversation_data = request_conversation_data[request_enter_offset+4:]
                elif request_conversation_data[request_enter_offset+4:request_enter_offset+8] == 'POST':
                    conversation_data.write(request_conversation_data[0:request_enter_offset+4])
                    request_conversation_data = request_conversation_data[request_enter_offset+4:]
                else:
                    conversation_data.write(request_data)
                    request_conversation_data = request_conversation_data[request_enter_offset+4+int(request_contentlength):]
            else:
                request_data = request_conversation_data[0:request_enter_offset]
                conversation_data.write(request_data)
                #写入一空行
                conversation_data.write('\r\n\r\n')
                request_conversation_data = request_conversation_data[request_enter_offset+4:]
        else:
            break
        #response处理
        #Date: 的偏移量
        response_date = response_conversation_data.find('Date: ')
        #换行部分的偏移量
        blank_flag = response_conversation_data[response_date:].find('\r\n\r\n')
        #Content-Length: 的偏移量
        response_contentlength = response_conversation_data[0:response_date+blank_flag].find('Content-Length: ')
        response_transferencoding = response_conversation_data[0:response_date+blank_flag].find('Transfer-Encoding: chunked')
        #对是否含有Content-Length进行不同的处理
        if response_contentlength > 0:
            #回车的偏移量，从Content-length开始算起
            content_length_enter = response_conversation_data[response_contentlength:].find('\r\n')
            #Content-Lenght的字符串部分
            content_length = response_conversation_data[response_contentlength+16:response_contentlength+content_length_enter]
            response_data = response_conversation_data[0:response_date+blank_flag+4+int(content_length)]
            conversation_data.write(response_data)
            response_conversation_data = response_conversation_data[response_date+blank_flag+4+int(content_length):]
        elif response_transferencoding>0:
            #chunk编码不知道数据部分多少字节，因此找两空行之间的部分为数据部分
            another_blank = response_conversation_data[response_date+blank_flag+4:].find('\r\n\r\n')
            response_data = response_conversation_data[0:response_date+blank_flag+another_blank+8]
            conversation_data.write(response_data)
            response_conversation_data = response_conversation_data[response_date+blank_flag+another_blank+8:]
        else:
            #其他情况只读取报文部分
            response_data = response_conversation_data[0:response_date+blank_flag+4]
            conversation_data.write(response_data)
            response_conversation_data = response_conversation_data[response_date+blank_flag+4:]
    #下一会话之后的数据部分
    request = request[request_conversation_offset+6:]
    response = response[response_conversation_offset+6:]
    #关闭某会话存储文件
    conversation_data.close()
    create_http_xml(conversation_filename)
    i += 1
    #将结果文件移动至result目录下
    shutil.copy(conversation_filename,file_path)
    os.remove(conversation_filename)

shutil.copy('request.txt',file_path)
shutil.copy('response.txt',file_path)
shutil.copy('result.txt',result_path)
shutil.copy('result.xml',result_path)
# shutil.copy('result.xsd',result_path)
os.remove('request.txt')
os.remove('response.txt')
os.remove('result.txt')
os.remove('result.xml')
#文件写入结束
finaldata_request.close()
finaldata_response.close()

#将DOM对象doc写入文件
dom = open('http.xml','w')
dom.write(doc.toprettyxml(indent = ''))
dom.close()

shutil.copy('http.xml',result_path)
os.remove('http.xml')

# dns_file_path = 'result/' +pcap_filename + '/' + 'dns/'
# #文件存在则覆盖
# if os.path.exists(dns_file_path):
#     shutil.rmtree(dns_file_path)
#     os.makedirs(dns_file_path)
# else:
#     os.makedirs(dns_file_path)
#
# finaldata_query = open('dns_query.txt','rb')
# string_query = finaldata_query.read()
# query = string_query
#
# finaldata_answer = open('dns_answer.txt','rb')
# string_answer = finaldata_answer.read()
# answer = string_answer
#
# j = 1
#
# while len(query) > 0:
#     dns_filename = 'result' + str(j) + '.txt'
#     dns_conversation_data = open(dns_filename,'wb')
#     query_offset = query.find('=====')
#     answer_offset = answer.find('=====')
#     query_conversation_data = query[0:query_offset]
#     answer_conversation_data = answer[0:answer_offset]
#     dns_conversation_data.write(query_conversation_data)
#     dns_conversation_data.write(answer_conversation_data)
#     query = query[query_offset+6:]
#     answer = answer[answer_offset+6:]
#     j+=1
#     dns_conversation_data.close()
#     shutil.copy(dns_filename,dns_file_path)
#     os.remove(dns_filename)
#
# shutil.copy('dns_query.txt',dns_file_path)
# shutil.copy('dns_answer.txt',dns_file_path)
# os.remove('dns_query.txt')
# os.remove('dns_answer.txt')
#
# finaldata_query.close()
# finaldata_answer.close()