#!/usr/bin/python3
#from formatm import *
from formatm_pb2 import *
import os
import logging
import tomlkit
import asyncio
import struct
from passlib.hash import sha256_crypt,sha512_crypt,argon2,bcrypt
from collections import defaultdict
import time
import sys    
async def read_data(reader):    
    blength= await reader.read(2)
    flength = struct.unpack(">H",blength)
    request_data = await reader.readexactly(flength[0])
    return request_data


def validate_user(username,password):
        if username in fhashes.keys():
                # compare hashes
                if(fhashes[username][1:7]=="argon2"):
                        if (argon2.verify(password,fhashes[username])):
                                return True
                        else:
                                return False
                elif(fhashes[username][0:3]=="$5$"):
                        if (sha256_crypt.verify(password,fhashes[username])):
                                return True
                        else:
                                return False
                elif(fhashes[username][0:2]=="$2"):
                        if (bcrypt.verify(password,fhashes[username])):
                                return True
                        else:
                                return False                        
                else: 
                        if (sha512_crypt.verify(password,fhashes[username])):
                                return True
                        else:
                                return False
        else:
                return False



def empty_block(src_ip):
    ip_count.clear()
    ip_time.clear()
    ip_set.clear()



async def handle_client(reader,writer):
       src_ip,src_port=writer.get_extra_info('peername')
       try:
         try: 
              request_data=await asyncio.wait_for(read_data(reader),timeout=10.0)
         except asyncio.TimeoutError:        
              writer.close()
              await writer.wait_closed()
         clrequest= Request()
         try:  
               clrequest.ParseFromString(request_data)
         except Exception as e:
              ip_set.add(src_ip)
              if src_ip not in ip_time.keys():
                   ip_time[src_ip]=time.time()
              ip_set.add(src_ip)
              ip_count[src_ip]+=1
              try:
                writer.close()
                await writer.wait_closed()
              except:
              	 pass  
         if clrequest.HasField("stop"):
              sr_response = Response()
              sr_response.stop.CopyFrom(StopResponse())
              serv_data=(sr_response.SerializeToString())
              writer.write(len(serv_data).to_bytes(2,byteorder="big"))
              writer.write(serv_data)    
              try:
                  await writer.drain()
                  writer.close() 
                  await writer.wait_closed() 
              except:
                  pass  
              os._exit(os.EX_OK)
 
         if clrequest.HasField("reset"):
              sr_response = Response()
              empty_block(src_ip)
              sr_response.reset.CopyFrom(ResetBlockListsResponse())
              serv_data=sr_response.SerializeToString()
              writer.write(len(serv_data).to_bytes(2,byteorder="big"))
              writer.write(serv_data)
              try:
                   await writer.drain()
                   writer.close()
                   await writer.wait_closed()
              except:
                    pass 
#              writer.close()
#              await writer.wait_closed()
         if(src_ip in ip_set or (ip_count[src_ip] >=3 and (time.time()-ip_time[src_ip]) <= 30)):
             writer.close()
             await writer.wait_closed()     
         if clrequest.HasField("expr"):
              sr_response = Response()
              if (len(clrequest.expr.username)==0 or len(clrequest.expr.password)==0):
                      writer.close()
                      await writer.wait_closed()
              result=validate_user(clrequest.expr.username,clrequest.expr.password)
              if result:
                      sr_response.expr.authenticated=True
                      try:
                              proc=await asyncio.create_subprocess_exec("python3","-c",clrequest.expr.expression,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
                              stdout,stderr= await asyncio.wait_for(proc.communicate(),timeout=5.0)
                              if stdout:
                                      sr_response.expr.result=stdout
                              if stderr:
                                  ip_set.add(src_ip)
                                  ip_count[src_ip]+=1
                                  if src_ip not in ip_time.keys():
                                      ip_time[src_ip]=time.time()
                      except:                           
                         writer.close()
                         await writer.wait_closed()
                      serv_data=sr_response.SerializeToString()
                      writer.write(len(serv_data).to_bytes(2,byteorder="big"))
                      writer.write(serv_data)
                      try:
                              await writer.drain()
                              writer.close()
                              await writer.wait_closed()
                      except:
                              pass
#                      writer.close()
#                      await writer.wait_closed()
              else:
                      ip_count[src_ip]+=1
                      if src_ip not in ip_time.keys():
                          ip_time[src_ip]=time.time()
                      sr_response.expr.authenticated=False
                      serv_data=sr_response.SerializeToString()
                      writer.write(len(serv_data).to_bytes(2,byteorder="big"))
                      writer.write(serv_data)
                      try:
                              await writer.drain()
                              writer.close()
                              await writer.wait_closed()
                      except:
                              pass
#                      writer.close()
#                      await writer.wait_closed()
         else:
              try:
               writer.close() 
               await writer.wait_closed()
              except:
                pass 
         
       except:
           pass
      



async def sem_auth(sem,r,w):
    async with sem:
        await handle_client(r,w)



async def main(host,port):
    hash_file= sys.argv[1]
    hashes=tomlkit.load(open(hash_file,"r"))
    global ip_time
    global ip_set
    global ip_count
    global fhashes
    ip_time=defaultdict(int)
    ip_set=set()
    ip_count = defaultdict(int)
    fhashes={}
    for user in hashes['users']:
        fhashes.update({user['username']:user['password_hash']})
    sem=asyncio.Semaphore(8)
    server = await asyncio.start_server(
            lambda r,w:sem_auth(sem,r,w), host, port)

    addrs = ', '.join(str(sock.getsockname()) for sock in server.sockets)

    async with server:
        await server.serve_forever()



if __name__ == "__main__":
    asyncio.run(main('0.0.0.0',1300))
