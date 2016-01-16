#!/usr/bin/env python
#coding:utf-8

#将pcap文件读取并将内容写入text文档
import struct
import operator
import dpkt
import datetime
from xml.dom.minidom import Document

try:
    import scapy.all as scapy
except ImportError:
    import scapy

class http:
    #定义http数据的序列号，数据，数据包序号，数据长度，源端口，目标端口，会话端口号
    def __init__(self,serial,datas,packet_num,data_len,sport,dport,conversation_port):
        self.serial = serial
        self.datas = datas
        self.packet_num = packet_num
        self.data_len = data_len
        self.sport = sport
        self.dport = dport
        self.conversation_port = conversation_port
    def classify_data_packet(self):
        #分割不同方向的会话
        if self.sport == 80:
            #判断端口号的列表中是否有数据
            if not len(response_port_assist):
                response_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
            if self.conversation_port in response_port_assist:
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
            elif self.conversation_port not in response_port_assist:
                sort_by_num(response_datalist,'serialnum')
                printhttp_finaldata(response_datalist)
                response_txt.write('='*5 + '\n')
                del(response_datalist[0:len(response_datalist)])
                response_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                response_datalist.append(conversationdata)
        elif self.dport == 80:
            if not len(request_port_assist):
                request_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)
            if self.conversation_port in request_port_assist:
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)
            elif self.conversation_port not in request_port_assist:
                sort_by_num(request_datalist,'serialnum')
                printhttp_finaldata(request_datalist)
                request_txt.write('='*5 + '\n')
                del(request_datalist[0:len(request_datalist)])
                request_port_assist.append(self.conversation_port)
                conversationdata = httpconversation(self.serial,self.datas,self.conversation_port,self.sport,self.dport,self.packet_num)
                request_datalist.append(conversationdata)

class httpconversation:
    def __init__(self,serialnum,finaldata,conversation_port,sport,dport,packet_num):
        self.serialnum = serialnum
        self.finaldata = finaldata
        self.conversation_port = conversation_port
        self.sport = sport
        self.dport = dport
        self.packet_num = packet_num
    def print_http_data(self):
        #response报文
        if self.sport == 80:
            #判断序列号列表中是否有数据
            if not len(response_serial_assist):
                response_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
            elif self.serialnum in response_serial_assist:
                data_assist.append(self.finaldata)
            elif self.serialnum not in response_serial_assist:
                responsemax_flag = max(data_assist)[0:4]
                #去除不规范的数据
                if responsemax_flag == 'GET ' or responsemax_flag == 'HEAD' or responsemax_flag == 'PUT ' or responsemax_flag == 'DELE' or responsemax_flag == 'POST' or responsemax_flag == 'OPTI' or responsemax_flag == 'TRAC':
                    print 'already delete useless information'
                elif max(data_assist) != '\r\n':
                    response_txt.write(max(data_assist))
                del(data_assist[0:len(data_assist)])
                response_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
        elif self.dport == 80:
            if not len(request_serial_assist):
                request_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)
            elif self.serialnum in request_serial_assist:
                data_assist.append(self.finaldata)
            elif self.serialnum not in request_serial_assist:
                #与相应报文的判断相反
                requestmax_flag = max(data_assist)[0:4]
                if requestmax_flag == 'GET ' or requestmax_flag == 'HEAD' or requestmax_flag == 'PUT ' or requestmax_flag == 'DELE' or requestmax_flag == 'POST' or requestmax_flag == 'OPTI' or requestmax_flag == 'TRAC':
                    request_txt.write(max(data_assist))
                del(data_assist[0:len(data_assist)])
                request_serial_assist.append(self.serialnum)
                data_assist.append(self.finaldata)

# class dns:
#     def __init__(self,data,sport,dport,dns_port):
#         self.data = data
#         self.sport = sport
#         self.dport = dport
#         self.dns_port = dns_port
#     def print_dns_data(self):
#         if self.sport == 53:
#             dns_answer.write(self.data)
#             dns_answer.write('='*5 + '\n')
#         elif self.dport ==53:
#             dns_query.write(self.data)
#             dns_query.write('='*5 + '\n')

#按照序列号排序
def sort_by_num(lst,attr):
    lst.sort(key=operator.attrgetter(attr))

def print_data_packet(lst):
    for per in lst:
        per.classify_data_packet()

def printhttp_finaldata(lst):
    for per in lst:
        per.print_http_data()
    flag = max(data_assist)[0:4]
    #每个会话中的最后序列号的数据包
    if flag == 'GET ' or flag == 'HEAD' or flag == 'PUT ' or flag == 'DELE' or flag == 'POST' or flag == 'OPTI' or flag == 'TRAC':
        request_txt.write(max(data_assist))
        del(data_assist[0:len(data_assist)])
    elif max(data_assist) == '\00':
        del(data_assist[0:len(data_assist)])
    elif max(data_assist) != '\r\n':
        response_txt.write(max(data_assist))
        del(data_assist[0:len(data_assist)])
    del(request_serial_assist[0:len(request_serial_assist)])
    del(response_serial_assist[0:len(response_serial_assist)])

#未压缩域名的解析
# 在域名长度大于0,即有域名可解析时，先读取域名中表示长度的字节，接着读取该长度的字节，最后以\00结尾
def dns_data_queries(domain_name,string):
    global uncompress_final_domain_name
    if len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
        if len(string) > 0:
            dns_data_queries(domain_name,string)
        else:
            result.write(domain_name[1:] + '\n')
            uncompress_final_domain_name = uncompress_final_domain_name + domain_name[1:]

#部分压缩域名情况处理，对未压缩部分数据取出来解析，压缩过的按照偏移量找到具体位置
def dns_data_queries_front(domain_name,string):
    if len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
        if len(string) > 0:
            dns_data_queries_front(domain_name,string)
        else:
            result.write(domain_name[1:] + '.')
            domain_name_list.append(domain_name[1:] + '.')

def dns_data_queries_behind(domain_name,string):
    if len(string) > 0:
        length = struct.unpack('b',string[0:1])[0]
        if length != 0:
            domain_name = domain_name + '.' +str(string[1:1+length])
        string = string[1+length:]
        dns_data_queries_behind(domain_name,string)
    elif len(string) == 0:
        result.write(domain_name[1:] + '\n')
        domain_name_behind = domain_name[1:]
        domain_name_list.append(domain_name_behind)

#dns_type情况解析
def dns_type_write(parent,dns_type):
    if dns_type == 1:
        result.write('Type：A (Host Address)' + '\n')
        create_xml(parent,'Type','A')
    elif dns_type == 2:
        result.write('Type：NS' + '\n')
        create_xml(parent,'Type','NS')
    elif dns_type == 5:
        result.write('Type：CNAME' + '\n')
        create_xml(parent,'Type','CNAME')
    elif dns_type == 6:
        result.write('Type：SOA' + '\n')
        create_xml(parent,'Type','SOA')
    elif dns_type == 11:
        result.write('Type：WKS' + '\n')
        create_xml(parent,'Type','WKS')
    elif dns_type == 12:
        result.write('Type：PTR' + '\n')
        create_xml(parent,'Type','PTR')
    elif dns_type == 13:
        result.write('Type：HINFO' + '\n')
        create_xml(parent,'Type','HINFO')
    elif dns_type == 15:
        result.write('Type：MX' + '\n')
        create_xml(parent,'Type','MX')
    elif dns_type == 16:
        result.write('Type：TXT' + '\n')
        create_xml(parent,'Type','TXT')
    elif dns_type == 17:
        result.write('Type：RP' + '\n')
        create_xml(parent,'Type','RP')
    elif dns_type == 18:
        result.write('Type：AFSDB' + '\n')
        create_xml(parent,'Type','AFSDB')
    elif dns_type == 24:
        result.write('Type：SIG' + '\n')
        create_xml(parent,'Type','SIG')
    elif dns_type == 25:
        result.write('Type：KEY' + '\n')
        create_xml(parent,'Type','KEY')
    elif dns_type == 28:
        result.write('Type：AAA' + '\n')
        create_xml(parent,'Type','AAA')
    elif dns_type == 29:
        result.write('Type：LOC' + '\n')
        create_xml(parent,'Type','LOC')
    elif dns_type == 33:
        result.write('Type：SRV' + '\n')
        create_xml(parent,'Type','SRV')
    elif dns_type == 35:
        result.write('Type：NAPTR' + '\n')
        create_xml(parent,'Type','NAPTR')
    elif dns_type == 36:
        result.write('Type：KX' + '\n')
        create_xml(parent,'Type','KX')
    elif dns_type == 37:
        result.write('Type：CERT' + '\n')
        create_xml(parent,'Type','CERT')
    elif dns_type == 39:
        result.write('Type：DNAME' + '\n')
        create_xml(parent,'Type','DNAME')
    elif dns_type == 41:
        result.write('Type：OPT' + '\n')
        create_xml(parent,'Type','OPT')
    elif dns_type == 42:
        result.write('Type：APL' + '\n')
        create_xml(parent,'Type','APL')
    elif dns_type == 43:
        result.write('Type：DS' + '\n')
        create_xml(parent,'Type','DS')
    elif dns_type == 44:
        result.write('Type：SSHFP' + '\n')
        create_xml(parent,'Type','SSHFP')
    elif dns_type == 45:
        result.write('Type：IPSECKEY' + '\n')
        create_xml(parent,'Type','IPSECKEY')
    elif dns_type == 46:
        result.write('Type：RRSIG' + '\n')
        create_xml(parent,'Type','RRSIG')
    elif dns_type == 47:
        result.write('Type：NSEC' + '\n')
        create_xml(parent,'Type','NSEC')
    elif dns_type == 48:
        result.write('Type：DNSKEY' + '\n')
        create_xml(parent,'Type','DNSKEY')
    elif dns_type == 49:
        result.write('Type：DHCID' + '\n')
        create_xml(parent,'Type','DHCID')
    elif dns_type == 50:
        result.write('Type：NSEC3' + '\n')
        create_xml(parent,'Type','NSEC3')
    elif dns_type == 51:
        result.write('Type：NSEC3PARAM' + '\n')
        create_xml(parent,'Type','NSEC3PARAM')
    elif dns_type == 52:
        result.write('Type：TLSA' + '\n')
        create_xml(parent,'Type','TLSA')
    elif dns_type == 55:
        result.write('Type：HIP' + '\n')
        create_xml(parent,'Type','HIP')
    elif dns_type == 59:
        result.write('Type：CDS' + '\n')
        create_xml(parent,'Type','CDS')
    elif dns_type == 60:
        result.write('Type：CDNSKEY' + '\n')
        create_xml(parent,'Type','CDNSKEY')
    elif dns_type == 249:
        result.write('Type：TKEY' + '\n')
        create_xml(parent,'Type','TKEY')
    elif dns_type == 250:
        result.write('Type：TSIG' + '\n')
        create_xml(parent,'Type','TSIG')
    elif dns_type == 251:
        result.write('Type：IXFR' + '\n')
        create_xml(parent,'Type','IXFR')
    elif dns_type == 252:
        result.write('Type：AXFR' + '\n')
        create_xml(parent,'Type','AXFR')
    elif dns_type == 255:
        result.write('Type：ANY' + '\n')
        create_xml(parent,'Type','ANY')
    elif dns_type == 257:
        result.write('Type：CAA' + '\n')
        create_xml(parent,'Type','CAA')
    elif dns_type == 32768:
        result.write('Type：TA' + '\n')
        create_xml(parent,'Type','TA')
    elif dns_type == 32769:
        result.write('Type：DLV' + '\n')
        create_xml(parent,'Type','DLV')
    else:
        result.write(str(dns_type) + '\n')
        create_xml(parent,'Type',str(dns_type))

#dns_class情况解析
def dns_class_write(parent,dns_class):
    if dns_class == 1:
        result.write('Class：IN' + '\n')
        create_xml(parent,'Class','IN')
    else:
        result.write(str(dns_class) + '\n')
        create_xml(parent,'Type',str(dns_class))

#answers部分的解析，包括type,class,ttl,data_length,cname或者address
def dns_answers_write(string,all_string):
    global domain_name_combine
    global uncompress_final_domain_name
    if len(string) > 0:
        data_length = struct.unpack('H',string[11:12]+string[10:11])[0]
        # print data_length
        answer_string = string[0:12+data_length]
        answer_string0 = struct.unpack('B',answer_string[0:1])[0]
        answer_string1 = struct.unpack('B',answer_string[1:2])[0]
        if answer_string0 == 192:
            dns_domain_string = all_string[answer_string1:]
            domain_end = dns_domain_string.find('\00')
            domain_compress = dns_domain_string.find('\xc0')
            if domain_end < domain_compress:
                domain = ''
                name_string = all_string[answer_string1:answer_string1+domain_end]
                result.write('Name：')
                dns_data_queries(domain,name_string)
                create_xml(answers,'Name',uncompress_final_domain_name)
                uncompress_final_domain_name = ''
            else:
                result.write('Name：')
                combine_domain(answer_string1,all_string)
                # print domain_name_list
                for each in domain_name_list:
                    domain_name_combine += each
                create_xml(answers,'Name',domain_name_combine)
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
        dns_type_write(answers,struct.unpack('H',answer_string[3:4]+answer_string[2:3])[0])
        dns_class_write(answers,struct.unpack('H',answer_string[5:6]+answer_string[4:5])[0])
        answer_ttl = struct.unpack('I',answer_string[9:10]+answer_string[8:9]+answer_string[7:8]+answer_string[6:7])[0]
        result.write('Time to live：' + repr(answer_ttl) + '\n')
        result.write('Data length：' + repr(data_length) + '\n')
        create_xml(answers,'Time_to_live',repr(answer_ttl))
        create_xml(answers,'Data_Length',repr(data_length))
        answer_type = struct.unpack('H',answer_string[3:4]+answer_string[2:3])[0]
        #解析了A,NS,和cname
        if answer_type == 1:
            address = str(struct.unpack('B',answer_string[12:13])[0]) + '.' + str(struct.unpack('B',answer_string[13:14])[0]) + '.' + str(struct.unpack('B',answer_string[14:15])[0]) + '.' + str(struct.unpack('B',answer_string[15:16])[0])
            result.write('Address：' + address + '\n')
            create_xml(answers,'Address',address)
        elif answer_type == 5:
            result.write('CNAME：')
            cname_string = string[12:12+data_length]
            cname_string_end = cname_string.find('\00')
            if cname_string_end > 0:
                domain = ''
                dns_data_queries(domain,string[12:12+cname_string_end])
                create_xml(answers,'CNAME',uncompress_final_domain_name)
                uncompress_final_domain_name = ''
            else:
                domain = ''
                cname_string_compress = cname_string.find('\xc0')
                dns_data_queries_front(domain,string[12:12+cname_string_compress])
                cname_string_offset = struct.unpack('B',string[13+cname_string_compress:14+cname_string_compress])[0]
                combine_domain(cname_string_offset,all_string)
                for each in domain_name_list:
                    domain_name_combine += each
                create_xml(answers,'CNAME',domain_name_combine)
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
        elif answer_type == 2:
            result.write('Name Server：')
            ns_string = string[12:12+data_length]
            ns_string_end = ns_string.find('\00')
            if ns_string_end > 0:
                domain = ''
                dns_data_queries(domain,string[12:12+ns_string_end])
                create_xml(answers,'Name_Server',uncompress_final_domain_name)
                uncompress_final_domain_name = ''
            else:
                domain = ''
                ns_string_compress = ns_string.find('\xc0')
                dns_data_queries_front(domain,string[12:12+ns_string_compress])
                ns_string_offset = struct.unpack('B',string[13+ns_string_compress:14+ns_string_compress])[0]
                combine_domain(ns_string_offset,all_string)
                for each in domain_name_list:
                    domain_name_combine += each
                create_xml(answers,'Name_Server',domain_name_combine)
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
        elif answer_type == 6:
            result.write('Primary name server：')
            soa_string = string[12:12+data_length]
            soa_string_end = soa_string.find('\00')
            soa_string_compress = soa_string.find('\xc0')
            print soa_string_end,soa_string_compress
            if soa_string_end < soa_string_compress:
                domain = ''
                dns_data_queries(domain,string[12:12+soa_string_end])
                create_xml(answers,'Primary_name_server',uncompress_final_domain_name)
                uncompress_final_domain_name = ''
                respon_string = string[13+soa_string_end:]
                respon_string_end = respon_string.find('\00')
                respon_string_compress = respon_string.find('\xc0')
                result.write('Responsible_authoritys_mailbox：')
                if respon_string_end < respon_string_compress:
                    domain = ''
                    dns_data_queries(domain,string[13+soa_string_end:13+soa_string_end+respon_string_end])
                    create_xml(answers,'Responsible_authoritys_mailbox',uncompress_final_domain_name)
                    uncompress_final_domain_name = ''

                    dns_serial_num = string[14+soa_string_end+respon_string_end:18+soa_string_end+respon_string_end]
                    dns_serial_num = struct.unpack('I',dns_serial_num)[0]
                    result.write('Serial Number：' + repr(dns_serial_num))
                    create_xml(answers,'Serial_Number',repr(dns_serial_num))

                    dns_refresh = string[18+soa_string_end+respon_string_end:22+soa_string_end+respon_string_end]
                    dns_refresh = struct.unpack('I',dns_refresh)[0]
                    result.write('Refersh_Interval：' + repr(dns_refresh))
                    create_xml(answers,'Refresh_Interval',repr(dns_refresh))

                    dns_retry = string[22+soa_string_end+respon_string_end:26+soa_string_end+respon_string_end]
                    dns_retry = struct.unpack('I',dns_retry)[0]
                    result.write('Retry_Interval：' + repr(dns_retry))
                    create_xml(answers,'Retry_Interval',repr(dns_retry))

                    dns_expire = string[26+soa_string_end+respon_string_end:30+soa_string_end+respon_string_end]
                    dns_expire = struct.unpack('I',dns_expire)[0]
                    result.write('Expire Limit：' + repr(dns_expire))
                    create_xml(answers,'Expire_Limit',repr(dns_expire))

                    dns_mini = string[30+soa_string_end+respon_string_end:34+soa_string_end+respon_string_end]
                    dns_mini = struct.unpack('I',dns_mini)[0]
                    result.write('Minimum TTL：' + repr(dns_mini))
                    create_xml(answers,'Minimun_TTL',repr(dns_mini))
                else:
                    domain = ''
                    dns_data_queries_front(domain,string[13+soa_string_end:13+soa_string_end+soa_string_compress])
                    respon_string_offset = struct.unpack('B',string[14+soa_string_end+soa_string_compress:15+soa_string_end+soa_string_compress])[0]
                    combine_domain(respon_string_offset,all_string)
                    for each in domain_name_list:
                        domain_name_combine += each
                    create_xml(answers,'Responsible_authoritys_mailbox',domain_name_combine)
                    del domain_name_list[0:len(domain_name_list)]
                    domain_name_combine = ''

                    dns_serial_num = string[15+soa_string_end+respon_string_compress:19+soa_string_end+respon_string_compress]
                    dns_serial_num = struct.unpack('I',dns_serial_num)[0]
                    result.write('Serial Number：' + repr(dns_serial_num))
                    create_xml(answers,'Serial_Number',repr(dns_serial_num))

                    dns_refresh = string[19+soa_string_end+respon_string_compress:23+soa_string_end+respon_string_compress]
                    dns_refresh = struct.unpack('I',dns_refresh)[0]
                    result.write('Refersh_Interval：' + repr(dns_refresh))
                    create_xml(answers,'Refresh_Interval',repr(dns_refresh))

                    dns_retry = string[23+soa_string_end+respon_string_compress:27+soa_string_end+respon_string_compress]
                    dns_retry = struct.unpack('I',dns_retry)[0]
                    result.write('Retry_Interval：' + repr(dns_retry))
                    create_xml(answers,'Retry_Interval',repr(dns_retry))

                    dns_expire = string[27+soa_string_end+respon_string_compress:31+soa_string_end+respon_string_compress]
                    dns_expire = struct.unpack('I',dns_expire)[0]
                    result.write('Expire Limit：' + repr(dns_expire))
                    create_xml(answers,'Expire_Limit',repr(dns_expire))

                    dns_mini = string[31+soa_string_end+respon_string_compress:35+soa_string_end+respon_string_compress]
                    dns_mini = struct.unpack('I',dns_mini)[0]
                    result.write('Minimum TTL：' + repr(dns_mini))
                    create_xml(answers,'Minimun_TTL',repr(dns_mini))
            else:
                domain = ''
                dns_data_queries_front(domain,string[12:12+soa_string_compress])
                soa_string_offset = struct.unpack('B',string[13+soa_string_compress:14+soa_string_compress])[0]
                combine_domain(soa_string_offset,all_string)
                for each in domain_name_list:
                    domain_name_combine += each
                create_xml(answers,'Primary_name_server',domain_name_combine)
                del domain_name_list[0:len(domain_name_list)]
                domain_name_combine = ''
                respon_string = string[14+soa_string_compress:]
                respon_string_end = respon_string.find('\00')
                respon_string_compress = respon_string.find('\xc0')
                result.write('Responsible_authoritys_mailbox：')
                if respon_string_end < respon_string_compress:
                    domain = ''
                    dns_data_queries(domain,string[14+soa_string_compress:14+soa_string_compress+respon_string_end])
                    create_xml(answers,'Responsible_authoritys_mailbox',uncompress_final_domain_name)
                    uncompress_final_domain_name = ''

                    dns_serial_num = string[16+soa_string_compress+respon_string_end:20+soa_string_compress+respon_string_end]
                    dns_serial_num = struct.unpack('I',dns_serial_num)[0]
                    result.write('Serial Number：' + repr(dns_serial_num))
                    create_xml(answers,'Serial_Number',repr(dns_serial_num))

                    dns_refresh = string[20+soa_string_compress+respon_string_end:24+soa_string_compress+respon_string_end]
                    dns_refresh = struct.unpack('I',dns_refresh)[0]
                    result.write('Refersh_Interval：' + repr(dns_refresh))
                    create_xml(answers,'Refresh_Interval',repr(dns_refresh))

                    dns_retry = string[24+soa_string_compress+respon_string_end:28+soa_string_compress+respon_string_end]
                    dns_retry = struct.unpack('I',dns_retry)[0]
                    result.write('Retry_Interval：' + repr(dns_retry))
                    create_xml(answers,'Retry_Interval',repr(dns_retry))

                    dns_expire = string[28+soa_string_compress+respon_string_end:32+soa_string_compress+respon_string_end]
                    dns_expire = struct.unpack('I',dns_expire)[0]
                    result.write('Expire Limit：' + repr(dns_expire))
                    create_xml(answers,'Expire_Limit',repr(dns_expire))

                    dns_mini = string[32+soa_string_compress+respon_string_end:36+soa_string_compress+respon_string_end]
                    dns_mini = struct.unpack('I',dns_mini)[0]
                    result.write('Minimum TTL：' + repr(dns_mini))
                    create_xml(answers,'Minimun_TTL',repr(dns_mini))
                else:
                    domain = ''
                    dns_data_queries_front(domain,string[14+soa_string_compress:14+soa_string_compress+soa_string_compress])
                    respon_string_offset = struct.unpack('B',string[15+soa_string_compress+soa_string_compress:16+soa_string_compress+soa_string_compress])[0]
                    combine_domain(respon_string_offset,all_string)
                    for each in domain_name_list:
                        domain_name_combine += each
                    create_xml(answers,'Responsible_authoritys_mailbox',domain_name_combine)
                    del domain_name_list[0:len(domain_name_list)]
                    domain_name_combine = ''

                    dns_serial_num = string[16+soa_string_compress+soa_string_compress:20+soa_string_compress+soa_string_compress]
                    dns_serial_num = struct.unpack('I',dns_serial_num)[0]
                    result.write('Serial Number：' + repr(dns_serial_num))
                    create_xml(answers,'Serial_Number',repr(dns_serial_num))

                    dns_refresh = string[20+soa_string_compress+soa_string_compress:24+soa_string_compress+soa_string_compress]
                    dns_refresh = struct.unpack('I',dns_refresh)[0]
                    result.write('Refersh_Interval：' + repr(dns_refresh))
                    create_xml(answers,'Refresh_Interval',repr(dns_refresh))

                    dns_retry = string[24+soa_string_compress+soa_string_compress:28+soa_string_compress+soa_string_compress]
                    dns_retry = struct.unpack('I',dns_retry)[0]
                    result.write('Retry_Interval：' + repr(dns_retry))
                    create_xml(answers,'Retry_Interval',repr(dns_retry))

                    dns_expire = string[28+soa_string_compress+soa_string_compress:32+soa_string_compress+soa_string_compress]
                    dns_expire = struct.unpack('I',dns_expire)[0]
                    result.write('Expire Limit：' + repr(dns_expire))
                    create_xml(answers,'Expire_Limit',repr(dns_expire))

                    dns_mini = string[32+soa_string_compress+soa_string_compress:36+soa_string_compress+soa_string_compress]
                    dns_mini = struct.unpack('I',dns_mini)[0]
                    result.write('Minimum TTL：' + repr(dns_mini))
                    create_xml(answers,'Minimun_TTL',repr(dns_mini))
        string = string[12+data_length:]
        dns_answers_write(string,all_string)

#解析压缩部分的，遇到\c0就读取之后的偏移量，并找到相应位置进行解析，多次压缩的情况进行递归解压
def combine_domain(offset,all_string):
    domain = ''
    part_string = all_string[offset:]
    part_string_end = part_string.find('\00')
    part_string_compress = part_string.find('\xc0')
    if part_string_end < part_string_compress:
        dns_data_queries_behind(domain,all_string[offset:offset+part_string_end])
    else:
        dns_data_queries_front(domain,all_string[offset:offset+part_string_compress])
        offset = struct.unpack('B',part_string[part_string_compress+1:part_string_compress+2])[0]
        combine_domain(offset,all_string)
# def print_dns_info(lst):
#     for per in lst:
#         per.print_dns_data()

#创建xml标签
def create_xml(parent,child_element,child_value):
    child = doc.createElement(child_element)
    child_text = doc.createTextNode(child_value)
    child.appendChild(child_text)
    parent.appendChild(child)

# pcapfile = 'multi.pcap'
pcapfile = raw_input('pcap_file:')
fpcap = open(pcapfile,'rb')
f = open(pcapfile)
pcap = dpkt.pcap.Reader(f)
#request.txt写入每个请求会话的数据
request_txt = open('request.txt','wb')
#response.txt写入每个相应会话的数据
response_txt = open('response.txt','wb')
#result.txt写入每个数据包的信息
result = open('result.txt','wb')
string_data = fpcap.read()
# dns_query = open('dns_query.txt','wb')
# dns_answer = open('dns_answer.txt','wb')

#临时存放数据的列表
request_serial_assist = []
response_serial_assist = []
request_port_assist = []
response_port_assist = []
request_datalist = []
response_datalist = []
data_assist = []
#存放数据包时间戳的列表
times = []

#获取数据包的时间并写入列表
for ts,buf in pcap:
    timestr = datetime.datetime.fromtimestamp(ts)
    times.append(str(timestr))

packets = scapy.rdpcap(pcapfile)
packet_num = 0
ip_num = 0
tcp_num = 0
http_packet_num = 0
dns_num = 0
#列表存放源mac地址，目标mac地址，源ip，目标ip
smacs = []
dmacs = []
sips = []
dips = []

uncompress_final_domain_name = ''
domain_name_combine = ''
domain_name_list = []

# #设置最大递归深度
# sys.setrecursionlimit(1000)

for p in packets:
    packet_num += 1
    for Ethernet in p.fields_desc:
        if Ethernet.name == 'src':
            Ethernetsrcvalue = p.src
            smacs.append(p.src)
        if Ethernet.name == 'dst':
            Ethernetdstvalue = p.dst
            dmacs.append(p.dst)
        if Ethernet.name == 'type':
            Ethernettypevalue = p.type
            if Ethernettypevalue == 2048:
                for IP in p.payload.fields_desc:
                    if IP.name == 'src':
                        #IP
                        ip_num += 1
                        IPsrcvalue = p.payload.getfieldval(IP.name)
                        reprval = IP.i2repr(p.payload,IPsrcvalue)
                        sips.append(IPsrcvalue)
                    if IP.name == 'dst':
                        IPdstvalue = p.payload.getfieldval(IP.name)
                        reprval = IP.i2repr(p.payload,IPdstvalue)
                        dips.append(IPdstvalue)

#pcap文件数据包解析
pcap_packet_header = {}
#起始packet数据包头位置,跳过pcap文件头
i =24
#起始数据链路头位置
j = 40
pcap_packet_mac = {}
#起始IP头位置
k = 54
#起始tcp或udp头位置
l = 74
packet_num = 0
ip_num = 0
tcp_num = 0
udp_num = 0
http_num = 0
#建立存放数据的字典
pcap_packet_ip = {}
pcap_packet_tcp = {}
pcap_packet_udp = {}
pcap_packet_dns = {}
ethernet_data = []
http_old_data = []
# dns_old_data = []
serial = []
conversation_port_list = []
# dns_port_list = []
#创建DOM文档对象
#创建DOM文档对象
doc = Document()
#创建根元素
network = doc.createElement('network')
#设置命名空间
network.setAttribute('xmlns:xsi',"http://www.w3.org/2001/XMLSchema-instance")
#引用本地XML Schema
network.setAttribute('xsi:noNamespaceSchemaLocation','result.xsd')
doc.appendChild(network)

while(i<len(string_data)):
      packet = doc.createElement('Packet')
      network.appendChild(packet)

      frame = doc.createElement('Frame')

      #数据包头各个字段，时间戳已读，直接从数据包长度读起
      #数据包长度
      pcap_packet_header['caplen'] = string_data[i+8:i+12]
      packet_caplen = struct.unpack('I',pcap_packet_header['caplen'])[0]

      #实际数据包长度
      pcap_packet_header['len'] = string_data[i+12:i+16]
      packet_len = struct.unpack('I',pcap_packet_header['len'])[0]
      result.write('NO.' + repr((packet_num+1)) + '\n')
      frame.setAttribute('NO',repr(packet_num+1))
      packet.appendChild(frame)
      result.write(times[packet_num] + '\n')
      result.write('Frame Length：' + repr(packet_caplen) + 'bytes' + '\n')
      result.write('Capture Length：' + repr(packet_len) + 'bytes' + '\n')
      create_xml(frame,'Arrival_Time',times[packet_num])
      create_xml(frame,'Frame_Length',repr(packet_caplen))
      create_xml(frame,'Capture_Length',repr(packet_len))

      #解析数据链路头
      #源Mac地址
      pcap_packet_mac['srcMac'] = string_data[j:j+6]
      #目的Mac地址
      pcap_packet_mac['dstMac'] = string_data[j+6:j+12]
      #类型
      pcap_packet_mac['type'] = string_data[j+12:j+14]
      result.write('Source：' + smacs[packet_num] + '\n')
      result.write('Destination：' + dmacs[packet_num] + '\n')
      ethernet = doc.createElement('Ethernet')
      packet.appendChild(ethernet)
      create_xml(ethernet,'Source',smacs[packet_num])
      create_xml(ethernet,'Destination',dmacs[packet_num])

      #是IP包
      if pcap_packet_mac['type'] == '\x08\x00':
          result.write('Type：IP' + '\n')
          create_xml(ethernet,'Type','IP')
          internet_protocol = doc.createElement('Internet_Protocol')
          packet.appendChild(internet_protocol)
          #解析IP头
          pcap_packet_ip['version'] = string_data[k:k+1]
          ip_version = struct.unpack('B',pcap_packet_ip['version'])[0]
          if ip_version == 69:
              result.write('version：IPV4' + '\n')
              create_xml(internet_protocol,'version','IPV4')
          elif ip_version == 101:
              result.write('version：IPV6' + '\n')
              create_xml(internet_protocol,'version','IPV6')

          pcap_packet_ip['tos'] = string_data[k+1:k+2]
          ip_tos = struct.unpack('B',pcap_packet_ip['tos'])[0]
          result.write('tos：' + repr(ip_tos) + '\n')
          create_xml(internet_protocol,'tos',repr(ip_tos))

          #总长度（IP+TCP+数据）
          pcap_packet_ip['totallen'] = string_data[k+2:k+4]
          pcap_packet_ip['totallen'] = pcap_packet_ip['totallen'][1:2] + pcap_packet_ip['totallen'][0:1]
          total_len = struct.unpack('H',pcap_packet_ip['totallen'])[0]
          result.write('Total Length：' + repr(total_len) + '\n')
          create_xml(internet_protocol,'Total_Length',repr(total_len))

          pcap_packet_ip['id'] = string_data[k+4:k+6]
          pcap_packet_ip['id'] = pcap_packet_ip['id'][1:2] + pcap_packet_ip['id'][0:1]
          ip_id = struct.unpack('H',pcap_packet_ip['id'])[0]
          result.write('Identification：' + repr(ip_id) + '\n')
          create_xml(internet_protocol,'Identification',repr(ip_id))

          pcap_packet_ip['flags'] = string_data[k+6:k+8]
          ip_flags = struct.unpack('H',pcap_packet_ip['flags'])[0]
          result.write('Flags：' + repr(ip_flags) + '\n')
          create_xml(internet_protocol,'Flags',repr(ip_flags))

          pcap_packet_ip['ttl'] = string_data[k+8:k+9]
          ip_ttl = struct.unpack('B',pcap_packet_ip['ttl'])[0]
          result.write('Time to live：' + repr(ip_ttl) + '\n')
          create_xml(internet_protocol,'Time_to_live',repr(ip_ttl))

          pcap_packet_ip['proto'] = string_data[k+9:k+10]
          ip_proto = struct.unpack('B',pcap_packet_ip['proto'])[0]
          if ip_proto == 6:
              result.write('Protocol：TCP' + '\n')
              create_xml(internet_protocol,'Protocol','TCP')
          elif ip_proto == 17:
              result.write('Protocol：UDP' + '\n')
              create_xml(internet_protocol,'Protocol','UDP')
          pcap_packet_ip['crc'] = string_data[k+10:k+12]
          pcap_packet_ip['sip'] = string_data[k+12:k+16]
          pcap_packet_ip['dip'] = string_data[k+16:k+20]
          result.write('Source：' + sips[ip_num] + '\n')
          result.write('Destination：' + dips[ip_num] + '\n')
          create_xml(internet_protocol,'Source',sips[ip_num])
          create_xml(internet_protocol,'Destination',dips[ip_num])
          ip_num += 1

          #TCP包
          if ip_proto == 6:
              tcp_num += 1
              transmission_control_protocol = doc.createElement('Transmission_Control_Protocol')
              packet.appendChild(transmission_control_protocol)
              pcap_packet_tcp['sport'] = string_data[l:l+2]
              pcap_packet_tcp['dport'] = string_data[l+2:l+4]
              pcap_packet_tcp['sport'] = pcap_packet_tcp['sport'][1:2]+pcap_packet_tcp['sport'][0:1]
              pcap_packet_tcp['dport'] = pcap_packet_tcp['dport'][1:2]+pcap_packet_tcp['dport'][0:1]
              sport = struct.unpack('H',pcap_packet_tcp['sport'])[0]
              dport = struct.unpack('H',pcap_packet_tcp['dport'])[0]
              result.write('Source Port：' + repr(sport) + '\n')
              result.write('Destination Port：' + repr(dport) + '\n')
              create_xml(transmission_control_protocol,'Source_Port',repr(sport))
              create_xml(transmission_control_protocol,'Destination_Port',repr(dport))

              pcap_packet_tcp['serial_num'] = string_data[l+4:l+8]
              pcap_packet_tcp['serial_num'] = pcap_packet_tcp['serial_num'][3:4] + pcap_packet_tcp['serial_num'][2:3] + pcap_packet_tcp['serial_num'][1:2] + pcap_packet_tcp['serial_num'][0:1]
              serial_num = struct.unpack('I',pcap_packet_tcp['serial_num'])[0]
              result.write('Sequence number：' + repr(serial_num) +'\n')
              create_xml(transmission_control_protocol,'Sequence_number',repr(serial_num))

              pcap_packet_tcp['ack_num'] = string_data[l+8:l+12]
              ack_num = struct.unpack('I',pcap_packet_tcp['ack_num'])[0]
              result.write('Acknowledgment number：' + repr(ack_num) + '\n')
              create_xml(transmission_control_protocol,'Acknowledgment_number',repr(ack_num))

              pcap_packet_tcp['tcplen'] = string_data[l+12:l+13]
              tcp_len_ascii = struct.unpack('B',pcap_packet_tcp['tcplen'])[0]
              tcp_len = tcp_len_ascii/4
              result.write('Header Length：' + repr(tcp_len) + 'bytes' + '\n')
              create_xml(transmission_control_protocol,'Header_Length',repr(tcp_len))

              pcap_packet_tcp['reserved'] = string_data[l+13:l+14]
              reserved = struct.unpack('B',pcap_packet_tcp['reserved'])[0]
              result.write('Reserved：' + repr(reserved) + '\n')
              create_xml(transmission_control_protocol,'Reserved',repr(reserved))

              pcap_packet_tcp['window'] = string_data[l+14:l+16]
              pcap_packet_tcp['window'] = pcap_packet_tcp['window'][1:2] + pcap_packet_tcp['window'][0:1]
              window = struct.unpack('h',pcap_packet_tcp['window'])[0]
              result.write('Window size value：' + repr(window) + '\n')
              create_xml(transmission_control_protocol,'Window_size_value',repr(window))

              pcap_packet_tcp['checksum'] = string_data[l+16:l+18]
              pcap_packet_tcp['checksum'] = pcap_packet_tcp['checksum'][1:2] + pcap_packet_tcp['checksum'][0:1]
              checksum = struct.unpack('H',pcap_packet_tcp['checksum'])[0]
              result.write('Checksum：' + repr(checksum) + '\n')
              create_xml(transmission_control_protocol,'Checksum',repr(checksum))

              pcap_packet_tcp['urgent_pointer'] = string_data[l+18:l+20]
              pcap_packet_tcp['urgent_pointer'] = pcap_packet_tcp['urgent_pointer'][1:2] + pcap_packet_tcp['urgent_pointer'][0:1]
              urgent_pointer = struct.unpack('H',pcap_packet_tcp['urgent_pointer'])[0]
              result.write('Urgent_pointer：' + repr(urgent_pointer) + '\n')
              create_xml(transmission_control_protocol,'Urgent_pointer',repr(urgent_pointer))

              if sport == 80:
                  conversation_port = dport
                  add_len = total_len - tcp_len - 20
                  pcap_packet_tcp['data'] = string_data[l+tcp_len:l+tcp_len+add_len]

                  if add_len>0:
                      http_info = http(serial_num,string_data[l+tcp_len:l+tcp_len+add_len],packet_num+1,add_len,sport,dport,conversation_port)
                      http_old_data.append(http_info)
                      http_num += 1
              elif dport == 80:
                  conversation_port = sport
                  add_len = total_len - tcp_len - 20
                  pcap_packet_tcp['data'] = string_data[l+tcp_len:l+tcp_len+add_len]

                  if add_len>0:
                      http_info = http(serial_num,string_data[l+tcp_len:l+tcp_len+add_len],packet_num+1,add_len,sport,dport,conversation_port)
                      http_old_data.append(http_info)
                      http_num += 1

          #UDP包
          elif ip_proto == 17:
              udp_num += 1
              user_datagram_protocol = doc.createElement('User_Datagram_Protocol')
              packet.appendChild(user_datagram_protocol)
              pcap_packet_udp['sport'] = string_data[l:l+2]
              pcap_packet_udp['dport'] = string_data[l+2:l+4]
              pcap_packet_udp['sport'] = pcap_packet_udp['sport'][1:2]+pcap_packet_udp['sport'][0:1]
              pcap_packet_udp['dport'] = pcap_packet_udp['dport'][1:2]+pcap_packet_udp['dport'][0:1]
              sport = struct.unpack('H',pcap_packet_udp['sport'])[0]
              dport = struct.unpack('H',pcap_packet_udp['dport'])[0]
              result.write('Source Port：' + repr(sport) + '\n')
              result.write('Destination Port：' + repr(dport) + '\n')
              create_xml(user_datagram_protocol,'Source_Port',repr(sport))
              create_xml(user_datagram_protocol,'Destination_Port',repr(dport))

              pcap_packet_udp['len'] = string_data[l+4:l+6]
              pcap_packet_udp['len'] = pcap_packet_udp['len'][1:2] + pcap_packet_udp['len'][0:1]
              udp_len = struct.unpack('H',pcap_packet_udp['len'])[0]
              result.write('Len：' + repr(udp_len) + '\n')
              create_xml(user_datagram_protocol,'Len',repr(udp_len))

              pcap_packet_udp['checksum'] = string_data[l+6:l+8]
              udp_checksum = struct.unpack('H',pcap_packet_udp['checksum'])[0]
              result.write('Checksum：' + repr(udp_checksum) +'\n')
              create_xml(user_datagram_protocol,'Checksum',repr(udp_checksum))

              if sport == 53 or dport == 53:
                  result.write('DNS' + '\n')
                  dns = doc.createElement('DNS')
                  user_datagram_protocol.appendChild(dns)
                  pcap_packet_dns['tran'] = string_data[l+8:l+10]
                  pcap_packet_dns['tran'] = pcap_packet_dns['tran'][1:2] + pcap_packet_dns['tran'][0:1]
                  tran = struct.unpack('H',pcap_packet_dns['tran'])[0]
                  result.write('Transaction ID：' + repr(tran) + '\n')
                  create_xml(dns,'Transaction_ID',repr(tran))

                  pcap_packet_dns['flags'] = string_data[l+10:l+12]
                  pcap_packet_dns['flags'] = pcap_packet_dns['flags'][1:2] + pcap_packet_dns['flags'][0:1]
                  dns_flags = struct.unpack('H',pcap_packet_dns['flags'])[0]
                  result.write('Flags：' + repr(dns_flags) + '\n')
                  create_xml(dns,'Flags',repr(dns_flags))

                  pcap_packet_dns['que'] = string_data[l+12:l+14]
                  pcap_packet_dns['que'] = pcap_packet_dns['que'][1:2] + pcap_packet_dns['que'][0:1]
                  que = struct.unpack('H',pcap_packet_dns['que'])[0]
                  result.write('Questions：' + repr(que) + '\n')
                  create_xml(dns,'Questions',repr(que))

                  pcap_packet_dns['ans'] = string_data[l+14:l+16]
                  pcap_packet_dns['ans'] = pcap_packet_dns['ans'][1:2] + pcap_packet_dns['ans'][0:1]
                  ans = struct.unpack('H',pcap_packet_dns['ans'])[0]
                  result.write('Answer RRS：' + repr(ans) + '\n')
                  create_xml(dns,'Answer_RRS',repr(ans))

                  pcap_packet_dns['auth'] = string_data[l+16:l+18]
                  pcap_packet_dns['auth'] = pcap_packet_dns['auth'][1:2] + pcap_packet_dns['auth'][0:1]
                  auth = struct.unpack('H',pcap_packet_dns['auth'])[0]
                  result.write('Anthority RRS：' + repr(auth) + '\n')
                  create_xml(dns,'Anthority_RRS',repr(auth))

                  pcap_packet_dns['add'] = string_data[l+18:l+20]
                  pcap_packet_dns['add'] = pcap_packet_dns['add'][1:2] + pcap_packet_dns['add'][0:1]
                  add = struct.unpack('H',pcap_packet_dns['add'])[0]
                  result.write('Additional RRS：' + repr(add) + '\n')
                  create_xml(dns,'Additional_RRS',repr(add))

                  pcap_packet_dns['data'] = string_data[l+20:l+udp_len]
                  dns_data = pcap_packet_dns['data']
                  #DNS报文的全部内容
                  dns_all_data = string_data[l+8:l+udp_len]
                  #分别处理源端口和目标端口为53端口的数据包
                  if sport == 53:
                      #超过DNS报文的长度
                      if len(dns_data) == 502:
                          result.write('Malformed Packet：DNS' + '\n')
                          mal = doc.createElement('Malformed')
                          dns.appendChild(mal)
                      else:
                          domain = ''
                          zeros = dns_data.find('\00')
                          #报文内容不正常，这里通过域名Name结束位判定
                          if zeros < 0:
                              result.write('Malformed Packet：DNS' + '\n')
                              mal = doc.createElement('Malformed')
                              dns.appendChild(mal)
                          else:
                              result.write('Queries：' + '\n')
                              queries = doc.createElement('Queries')
                              dns.appendChild(queries)
                              result.write('Name：')
                              #domainName部分
                              dns_domain = dns_data[0:zeros]
                              #对域名进行解析，这里是Queries中的未压缩的域名情况
                              dns_data_queries(domain,dns_domain)
                              create_xml(queries,'Name',uncompress_final_domain_name)
                              uncompress_final_domain_name = ''
                              #解析type字段并进行判断
                              dns_type = struct.unpack('H',dns_data[zeros+2:zeros+3]+dns_data[zeros+1:zeros+2])[0]
                              dns_type_write(queries,dns_type)
                              #解析class字段并进行判断
                              dns_class = struct.unpack('H',dns_data[zeros+4:zeros+5]+dns_data[zeros+3:zeros+4])[0]
                              dns_class_write(queries,dns_class)
                              result.write('Answers：' + '\n')
                              answers = doc.createElement('Answers')
                              dns.appendChild(answers)
                              #取Answers部分的数据并进行解析
                              dns_answer_data = dns_data[zeros+5:]
                              try:
                                  dns_answers_write(dns_answer_data,dns_all_data)
                              except Exception, ex:
                                  mal = doc.createElement('Malformed')
                                  answers.appendChild(mal)


                  elif dport == 53:
                      if len(dns_data) == 502:
                          result.write('Malformed Packet：DNS' + '\n')
                          mal = doc.createElement('Malformed')
                          dns.appendChild(mal)
                      else:
                          domain = ''
                          zeros = dns_data.find('\00')
                          if zeros < 0:
                              result.write('Malformed Packet：DNS' + '\n')
                              mal = doc.createElement('Malformed')
                              dns.appendChild(mal)
                          else:
                              result.write('Queries：' + '\n')
                              queries = doc.createElement('Queries')
                              dns.appendChild(queries)
                              result.write('Name：')
                              dns_domain = dns_data[0:zeros]
                              dns_data_queries(domain,dns_domain)
                              # print final_domain_name
                              create_xml(queries,'Name',uncompress_final_domain_name)
                              uncompress_final_domain_name = ''
                              dns_type = struct.unpack('H',dns_data[zeros+2:zeros+3]+dns_data[zeros+1:zeros+2])[0]
                              dns_type_write(queries,dns_type)
                              dns_class = struct.unpack('H',dns_data[zeros+4:zeros+5]+dns_data[zeros+3:zeros+4])[0]
                              dns_class_write(queries,dns_class)
                  # if sport == 53:
                  #     dns_port = dport
                  #     dns_info = dns(dns_data,sport,dport,dns_port)
                  #     dns_old_data.append(dns_info)
                  # elif dport == 53:
                  #     dns_port = sport
                  #     dns_info = dns(dns_data,sport,dport,dns_port)
                  #     dns_old_data.append(dns_info)
      else:
          result.write('Type：Non-IP' + '\n')
          create_xml(ethernet,'Type','Non-IP')

      result.write('*'*50 + '\n')

      #写入此包数据
      i = i + packet_len+16
      j = j + packet_len+16
      k = k + packet_len+16
      l = l + packet_len+16
      packet_num+=1

#统计输出不同个类型数据包的数量
print '数据包数量是：' + repr(packet_num)
print 'ip包数量是：' + repr(ip_num)
print 'tcp包数量是：' + repr(tcp_num)
print 'http包数量是：' + repr(http_num)

#http输出处理
sort_by_num(http_old_data,'conversation_port')
print_data_packet(http_old_data)
#最后一段会话运行函数对会话进行处理
sort_by_num(request_datalist,'serialnum')
printhttp_finaldata(request_datalist)
request_txt.write('='*5)
sort_by_num(response_datalist,'serialnum')
printhttp_finaldata(response_datalist)
response_txt.write('='*5)

# #dns输出处理
# sort_by_num(dns_old_data,'dns_port')
# print_dns_info(dns_old_data)

#文件写入结束
request_txt.close()
response_txt.close()
fpcap.close()
result.close()
# dns_query.close()
# dns_answer.close()

#将DOM对象doc写入文件
dom = open('result.xml','w')
dom.write(doc.toprettyxml(indent = ''))
dom.close()