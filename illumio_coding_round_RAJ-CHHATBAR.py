import pandas as pd
import abc



class ABC_Firewall(object, metaclass=abc.ABCMeta):
    
    """Create a abstract base class for Firewall class 
    where defining accept packet is compulsory"""
    
    @abc.abstractmethod
    def accept_packet(self,):
        raise NotImplementedError('users must define accept_packet functions')
        
        
class Firewall(ABC_Firewall):
    
    """ Creating Firewall class which accepts csv
    Plus defining accept_packet method"""
    
    def __init__(self, file_path):
        self.file_path=file_path
        
        self.data_firewall=pd.read_csv(self.file_path)
        #fw=Firewall("/home/Raj/Desktop/test.csv")  to call Firewall
        self.groupby_inbound=self.data_firewall[self.data_firewall['direction']=='inbound']
        self.groupby_outbound=self.data_firewall[self.data_firewall['direction']=='outbound']
        del self.data_firewall
        
        #-----------------------------------------INBOUND-------------------------
        self.groupby_inbound_tcp=self.groupby_inbound[self.groupby_inbound['protocol']=='tcp']
        self.groupby_inbound_udp=self.groupby_inbound[self.groupby_inbound['protocol']=='udp']
        del self.groupby_inbound
        
        #-----------------------------------------OUTBOUND---------------------------
        self.groupby_outbound_tcp=self.groupby_outbound[self.groupby_outbound['protocol']=='tcp']
        self.groupby_outbound_udp=self.groupby_outbound[self.groupby_outbound['protocol']=='udp']
        del self.groupby_outbound
        
        
        
    def validate_port(self,port):
        if port>65535 or port<0:
            return 0
        else:
            return 1
    def validate_direction(self,direction):
        if direction=='inbound' or direction =='outbound':
            return 1
        else:
            return 0
    def validate_protocol(self,protocol):
        if protocol=='tcp' or protocol=='udp':
            return 1
        else:
            return 0
    def validate_ip_address(self,ip_address):
        ip=[ip_address.split('.')]
        if len(ip)==4:
            for x in ip:
                if x<0 or x>255:
                    return 0
        else:
            return 1
            
    
    def accept_packet(self, direction , protocol , port , ip_address):
        
        #fw.accept_packet('inbound','tcp',80,'192.168.2.6') to call method
        if  self.validate_direction(direction):
            pass
        else:
            return False
        
        if  self.validate_protocol(protocol):
            pass
        else:   
            return False
        
        if  self.validate_port(port):
            pass
        else:
            return False
        if  self.validate_ip_address(ip_address):
            pass
        else: 
            return False
        

        #-------------------------------------------------------------------
        if direction=='inbound' and protocol=='tcp':
            port_flag=False
            ip_flag=False
            for index, row in self.groupby_inbound_tcp.iloc[:,2:4].iterrows():
                 port_range=row['port'].split("-")
                 if len(port_range)==2:
                     if port>=int(port_range[0]) and port<=int(port_range[1]):
                         port_flag=True
                     else:
                         port_flag=False
                 elif len(port_range)==1:
                     if port==int(port_range[0]):
                         port_flag=True
                     else:
                         port_flag=False
                             
                 ip_range=row['ipaddress'].split("-")
                 actual_ip=ip_address.split(".")
                 if len(ip_range)==2:
                     start_range=ip_range[0].split(".")
                     end_range=ip_range[1].split(".")
                     for x in range(0,len(actual_ip)):
                         if int(actual_ip[x])>=int(start_range[x]) and int(actual_ip[x])<=int(end_range[x]):
                             ip_flag=True
                         else:
                             ip_flag=False
                 elif len(ip_range)==1:
                     if ip_range[0]==ip_address:
                         ip_flag=True
                     else:
                         ip_flag=False
                 if ip_flag==True and port_flag==True:
                     return True
            
            return False  



        if direction=='inbound' and protocol=='udp':
            port_flag=False
            ip_flag=False
            for index, row in self.groupby_inbound_tcp.iloc[:,2:4].iterrows():
                 port_range=row['port'].split("-")
                 if len(port_range)==2:
                     if port>=int(port_range[0]) and port<=int(port_range[1]):
                         port_flag=True
                     else:
                         port_flag=False
                 elif len(port_range)==1:
                     if port==int(port_range[0]):
                         port_flag=True
                     else:
                         port_flag=False
                             
                 ip_range=row['ipaddress'].split("-")
                 actual_ip=ip_address.split(".")
                 if len(ip_range)==2:
                     start_range=ip_range[0].split(".")
                     end_range=ip_range[1].split(".")
                     for x in range(0,len(actual_ip)):
                         if int(actual_ip[x])>=int(start_range[x]) and int(actual_ip[x])<=int(end_range[x]):
                             ip_flag=True
                         else:
                             ip_flag=False
                 elif len(ip_range)==1:
                     if ip_range[0]==ip_address:
                         ip_flag=True
                     else:
                         ip_flag=False
                 if ip_flag==True and port_flag==True:
                     return True
            
            return False  


            
        if direction=='outbound' and protocol=='tcp':
            port_flag=False
            ip_flag=False
            for index, row in self.groupby_inbound_tcp.iloc[:,2:4].iterrows():
                 port_range=row['port'].split("-")
                 if len(port_range)==2:
                     if port>=int(port_range[0]) and port<=int(port_range[1]):
                         port_flag=True
                     else:
                         port_flag=False
                 elif len(port_range)==1:
                     if port==int(port_range[0]):
                         port_flag=True
                     else:
                         port_flag=False
                             
                 ip_range=row['ipaddress'].split("-")
                 actual_ip=ip_address.split(".")
                 if len(ip_range)==2:
                     start_range=ip_range[0].split(".")
                     end_range=ip_range[1].split(".")
                     for x in range(0,len(actual_ip)):
                         if int(actual_ip[x])>=int(start_range[x]) and int(actual_ip[x])<=int(end_range[x]):
                             ip_flag=True
                         else:
                             ip_flag=False
                 elif len(ip_range)==1:
                     if ip_range[0]==ip_address:
                         ip_flag=True
                     else:
                         ip_flag=False
                 if ip_flag==True and port_flag==True:
                     return True
            
            return False  

 
        
        if direction=='outbound' and protocol=='udp':
            port_flag=False
            ip_flag=False
            for index, row in self.groupby_inbound_tcp.iloc[:,2:4].iterrows():
                 port_range=row['port'].split("-")
                 if len(port_range)==2:
                     if port>=int(port_range[0]) and port<=int(port_range[1]):
                         port_flag=True
                     else:
                         port_flag=False
                 elif len(port_range)==1:
                     if port==int(port_range[0]):
                         port_flag=True
                     else:
                         port_flag=False
                             
                 ip_range=row['ipaddress'].split("-")
                 actual_ip=ip_address.split(".")
                 if len(ip_range)==2:
                     start_range=ip_range[0].split(".")
                     end_range=ip_range[1].split(".")
                     for x in range(0,len(actual_ip)):
                         if int(actual_ip[x])>=int(start_range[x]) and int(actual_ip[x])<=int(end_range[x]):
                             ip_flag=True
                         else:
                             ip_flag=False
                 elif len(ip_range)==1:
                     if ip_range[0]==ip_address:
                         ip_flag=True
                     else:
                         ip_flag=False
                 if ip_flag==True and port_flag==True:
                     return True
            
            return False  

     