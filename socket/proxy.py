#!/usr/bin/env python
# -*- coding:utf-8 -*-
import sys
import socket
import threading

def response_handler(buffer):
    return buffer

def request_handler(buffer):
    return buffer

def receive_from(connection):
    buffer = ""
    connection.settimeout(2)
    try:
        while True:
            data = connection.recv(4096)
            if not data:
                break
            buffer += data
    except:
        pass
    return buffer

def hexdump(src, length = 16):
    result = []

    digits = 4 if isinstance(src, unicode) else 2

    for i in xrange(0, len(src), length):
        s = src[i: i+length]
        hexa = b' '.join(["%0*X" %(digits, ord(x)) for x in s])
        text = b''.join([x if 0x20 <= ord(x) < 0x7F else b'.' for x in s])
        result.append(b"%04x  %-*s  %s" %(i, length*(digits + 1), hexa, text))
    print b'\n'.join(result)

def server_loop(local_host,local_port,remote_host,remote_port,receive_first):
    server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    try:
        server_socket.bind((local_host,local_port))
    except:
        print ("Listen Error!%s:%d"%(local_host,local_port))
        sys.exit(0)
    print ("Listening : %s:%d"%(local_host,local_port))
    server_socket.listen(5)
    while True:
        client_socket,addr = server_socket.accept()
        print ("Receive from to %s:%d"%(addr[0],addr[1]))
        proxy_thread = threading.Thread(target=proxy_handler,args=(client_socket,remote_host,remote_port,receive_first))
        proxy_thread.start()

# 持续从本地读取数据、处理、发送到远程主机，
# 从远程读取数据、处理、发送回本地主，直到所有数据都处理完毕
def proxy_handler(client_socket, remote_host, remote_port, receive_first):
    #设置远程连接
    remote_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    remote_socket.connect((remote_host,remote_port))

    #如果先接到数据
    if receive_first:

        remote_buffer = receive_from(remote_socket)
        hexdump(remote_buffer)

        remote_buffer = response_handler(remote_buffer)
        
        #如果有数据，则发送
        if len(remote_buffer):

            print ("[<===]Sending to %d bytes localhost."%len(remote_buffer))

            client_socket.send(remote_buffer)
    #循环读取数据
    while True:
        #本地读取数据
        local_buffer = receive_from(client_socket)

        if len(local_buffer):
            print ("[===>] Received %d bytes from localhost"%len(local_buffer))

            hexdump(local_buffer)
            #发送给本地请求
            local_buffer = request_handler(local_buffer)

            #向远程发送数据
            remote_socket.send(local_buffer)
            print ("[===>]Send to  bytes remote")

        #接收数据
        remote_buffer = receive_from(remote_socket)
        if len(remote_buffer):

            print ("[<===] Received %d bytes from remote"%len(remote_buffer))

            hexdump(remote_buffer)
            #发送到响应处理
            remote_buffer = response_handler(remote_buffer)

            #发送到本地socket
            client_socket.send(remote_buffer)
            print ("[<===] Send to bytes localhost")
        # 如果两边都没有数据，关闭连接
        if not len(local_buffer) or not len(remote_buffer):
            client_socket.close()
            remote_socket.close()
            print "[*] No more data. Closing connections."
            break



def main():
    if len(sys.argv[1:]) != 5:
        print ("error")
        sys.exit(0)
    local_host =sys.argv[1]
    local_port =int(sys.argv[2])
    remote_host =sys.argv[3]
    remote_port =int(sys.argv[4])
    receive_first =sys.argv[5]

    if "True" in receive_first:
        receive_first = True
    else:
        receive_first = False

    server_loop(local_host,local_port,remote_host,remote_port,receive_first)

main()