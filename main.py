'''
--------------------------------------------------------
----------      SYSLOG - TO - CSV        ---------------
--------------------------------------------------------
Problem: extracting data from syslogs into a table ready 
        format.
Target Users: Linux users
Target System: GNU/Linux
Interface: Command-line
Functional Requirements:    - open zipped logfiles
                            - open active logfiles
                            - read all data
                            - sort data
                            - save all data as csv
Testing: using user sumbmitted syslogs
Maintainer: frederickluckham@gmail.com
--------------------------------------------------------

This tool is designed to read syslog files and extract
the contents into a csv format. It uses regular expressions
to extract all data and sort it correctly into a Pandas
Dataframe. This was designed for personal use with my own
syslog files, so it may not work with all formats.

--------------------------------------------------------
'''

import gzip 
import re
import pandas as pd
import numpy as np

#Make Lists
timestamp_list = []
year_list = []
month_list = []
day_list = []
time_list = []
device_list = []
service_list = []
ufwrule_list = []
status_list = []
message_list = []
source_list = []
destination_list = []
physinput_list = [] 
input_list = []
output_list = []
physoutput_list = []
macaddress_list = []
length_list = []
tos_list = []
precedence_list = []
ttl_list = []
id_list = []
flag_list = []
protocol_list = []
sourceport_list = []
destinationport_list = []
recseq_list = []
ackseq_list = []
window_list = []
reserved_list = []
synurgp_list = []

#Compile the regex patterns
ts_pattern = re.compile(r'((Jan|Feb|Mar|Apr|May|Jun|Jul|Apr|Sep|Oct|Nov|Dec)\s+(\d+)\s+((0[0-9]|1[0-9]|2[0-3])(\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])(\:)(0[0-9]|1[0-9]|2[0-9]|3[0-9]|4[0-9]|5[0-9])))')
mth_pattern = re.compile(r'(?P<Month>Jan|Feb|Mar|Apr|May|Jun|Jul|Apr|Sep|Oct|Nov|Dec\s+\d+\s+)')
dy_pattern = re.compile(r'\s+(?P<Day>\d+)\s+')
tme_pattern = re.compile(r'(?P<Time>([01]?\d|2[0-3]|24(?=:00?:00?$)):([0-5]\d):([0-5]\d))')
src_pattern = re.compile(r'\sSRC.*?=?(?P<Source>[0-9a-f\.]*)')
dst_pattern = re.compile(r'\sDST.*?=(?P<Destination>[0-9a-f\.]*)')
dvc_pattern = re.compile(r'((([01]?\d|2[0-3]|24(?=:00?:00?$)):([0-5]\d):([0-5]\d))\s)(?P<Device>\S+)')
status_pattern = re.compile(r'((\bkernel:\s\b)(?P<StatusEvent>((eth|br|dev|Ker).*)))')
svc_pattern = re.compile(r'((([01]?\d|2[0-3]|24(?=:00?:00?$)):([0-5]\d):([0-5]\d))\s)(\S+)\s(?P<Service>(?:(?!:).)*)')
msg_pattern = re.compile(r'((([01]?\d|2[0-3]|24(?=:00?:00?$)):([0-5]\d):([0-5]\d))\s)(\S+)\s((?:(?!\s).)*)(?P<Message>.*)')
ufw_pattern = re.compile(r'(\bUFW\s\b)(?P<UFWRule>[^]\s]+)')
in_pattern = re.compile(r'((\bIN=\b)(?P<Input>[^\s]+))')
physin_pattern = re.compile(r'((\bPHYSIN=\b)(?P<PhysicalInput>[^\s]+))')
out_pattern = re.compile(r'((\bOUT=\b)(?P<Output>[^\s]+))')
physout_pattern = re.compile(r'((\bPHYSOUT=\b)(?P<PhysicalOutput>[^\s]+))')
mac_pattern = re.compile(r'((\bMAC=\b)(?P<MACAddress>[^\s]+))')
len_pattern = re.compile(r'((\bLEN=\b)(?P<PacketLength>[^\s]+))')
tos_pattern = re.compile(r'((\bTOS=\b)(?P<TypeOfService>[^\s]+))')
prec_pattern = re.compile(r'((\bPREC=\b)(?P<Precedence>[^\s]+))')
ttl_pattern = re.compile(r'((\bTTL=\b)(?P<TimeToLive>[^\s]+))')
id_pattern = re.compile(r'((\bID=\b)(?P<ID>[^\s]+))')
flag_pattern = re.compile(r'(?P<Flag>\b\sCE|DF|MF\s\b)')
prtc_pattern = re.compile(r'((\bPROTO=\b)(?P<Protocol>[^\s]+))')
spt_pattern = re.compile(r'((\bSPT=\b)(?P<SourcePort>[^\s]+))')
dpt_pattern = re.compile(r'((\bDPT=\b)(?P<DestinationPort>[^\s]+))')
recseq_pattern = re.compile(r'((\bSEQ=\b)(?P<SequenceNumber>[^\s]+))')
ackseq_pattern = re.compile(r'((\bSEQ=\b)(?P<AcknowledgementNumber>[^\s]+))')
win_pattern = re.compile(r'((\bWINDOW=\b)(?P<Window>[^\s]+))')
res_pattern = re.compile(r'((\bRES=\b)(?P<Reserved>[^\s]+))')
synurgp_pattern = re.compile(r'((\bSYN\sURGP=\b)(?P<SynUrgp>[^\s]+))')


#Write opened arhives to file and read line by line
def open_archive():
    try:
        in_path_fn = input("Enter full path, file name, and extension: ") 
        if ".gz" in in_path_fn: 
            outfile = gzip.open('{0}'.format(in_path_fn),'rt')
        else:
            outfile = open('{0}'.format(in_path_fn), 'rt')
        data = outfile.readlines()
        outfile.close()
        
    except Exception as e:
        print("Unable to find path / file. Are you sure you entered it correctly?")
    
    else:
        reg_search(data)



#Perform regex serach on each line, output to lists
def reg_search(file):
    try:
        message_check = 'IN='
        for line in file:
            timestamp_search = re.search(ts_pattern, line)
            if timestamp_search:
                timestamp = timestamp_search.group(1)
                timestamp_list.append(timestamp)
            else:
                time_list.append('na')
            
            month_search = re.search(mth_pattern, line)
            if month_search:
                month = month_search.group(1)
                month_list.append(month)
            else:
                month_list.append('na')
            
            day_search = re.search(dy_pattern, line)
            if day_search:
                day = day_search.group(1)
                day_list.append(day)
            else:
                day_list.append('na')

            time_search = re.search(tme_pattern, line)
            if time_search:
                time = time_search.group(1)
                time_list.append(time)
            else:
                time_list.append('na')

            device_search = re.search(dvc_pattern, line)
            if device_search:
                device = device_search.group('Device')
                device_list.append(device)
            else:
                device_list.append('na')

            service_search = re.search(svc_pattern, line)
            if service_search:
                service = service_search.group('Service')
                service_list.append(service)
            else:
                service_list.append('na')

            message_search = re.search(msg_pattern, line)
            if message_search:
                message = message_search.group('Message')
                if message_check not in line:
                    message_list.append(message)
                else:
                    message_list.append('na')           
            else:
                message_list.append('na')

            status_search = re.search(status_pattern, line)
            if status_search:
                status = status_search.group(1)
                status_list.append(status)
            else:
                status_list.append('na')

            ufw_search = re.search(ufw_pattern, line)
            if ufw_search:
                ufwrule = ufw_search.group('UFWRule')
                ufwrule_list.append(ufwrule)
            else:
                ufwrule_list.append('na')

            source_search = re.search(src_pattern, line)
            if source_search:
                source = source_search.group('Source')
                source_list.append(source)
            else:
                source_list.append('na')

            destination_search = re.search(dst_pattern, line)
            if destination_search:
                destination = destination_search.group('Destination')
                destination_list.append(destination)
            else:
                destination_list.append('na')

            in_search = re.search(in_pattern, line)
            if in_search:
                inputs = in_search.group('Input')
                input_list.append(inputs)
            else:
                input_list.append('na')

            physin_search = re.search(physin_pattern, line)
            if physin_search:
                physinputs = physin_search.group('PhysicalInput')
                physinput_list.append(physinputs)
            else:
                physinput_list.append('na')

            out_search = re.search(out_pattern, line)
            if out_search:
                outputs = out_search.group('Output')
                output_list.append(outputs)
            else:
                output_list.append('na')            

            physout_search = re.search(physout_pattern, line)
            if physout_search:
                physoutputs = physout_search.group('PhysicalOutput')
                physoutput_list.append(physoutputs)
            else:
                physoutput_list.append('na')  

            mac_search = re.search(mac_pattern, line)
            if mac_search:
                mac = mac_search.group('MACAddress')
                macaddress_list.append(mac)
            else:
                macaddress_list.append('na')          

            len_search = re.search(len_pattern, line)
            if len_search:
                length = len_search.group('PacketLength')
                length_list.append(length)
            else:
                length_list.append('na')    

            tos_search = re.search(tos_pattern, line)
            if tos_search:
                tos = tos_search.group('TypeOfService')
                tos_list.append(tos)
            else:
                tos_list.append('na')    

            prec_search = re.search(prec_pattern, line)
            if prec_search:
                prec = prec_search.group('Precedence')
                precedence_list.append(prec)
            else:
                precedence_list.append('na')   

            ttl_search = re.search(ttl_pattern, line)
            if ttl_search:
                ttl = ttl_search.group('TimeToLive')
                ttl_list.append(ttl)
            else:
                ttl_list.append('na')   

            id_search = re.search(id_pattern, line)
            if id_search:
                identry = id_search.group('ID')
                id_list.append(identry)
            else:
                id_list.append('na')   

            flag_search = re.search(flag_pattern, line)
            if flag_search:
                flag = flag_search.group('Flag')
                flag_list.append(flag)
            else:
                flag_list.append('na')   

            prtc_search = re.search(prtc_pattern, line)
            if prtc_search:
                prtc = prtc_search.group('Protocol')
                protocol_list.append(prtc)
            else:
                protocol_list.append('na')   

            spt_search = re.search(spt_pattern, line)
            if spt_search:
                spt = spt_search.group('SourcePort')
                sourceport_list.append(spt)
            else:
                sourceport_list.append('na')   

            dpt_search = re.search(dpt_pattern, line)
            if dpt_search:
                dpt = dpt_search.group('DestinationPort')
                destinationport_list.append(dpt)
            else:
                destinationport_list.append('na')   

            recseq_search = re.search(recseq_pattern, line)
            if recseq_search:
                recseq = recseq_search.group('SequenceNumber')
                recseq_list.append(recseq)
            else:
                recseq_list.append('na')   

            ackseq_search = re.search(ackseq_pattern, line)
            if ackseq_search:
                ackseq = ackseq_search.group('AcknowledgementNumber')
                ackseq_list.append(ackseq)
            else:
                ackseq_list.append('na')   

            win_search = re.search(win_pattern, line)
            if win_search:
                win = win_search.group('Window')
                window_list.append(win)
            else:
                window_list.append('na')   

            res_search = re.search(res_pattern, line)
            if res_search:
                res = res_search.group('Reserved')
                reserved_list.append(res)
            else:
                reserved_list.append('na')   

            synurgp_search = re.search(synurgp_pattern, line)
            if synurgp_search:
                synurgp = synurgp_search.group('SynUrgp')
                synurgp_list.append(synurgp)
            else:
                synurgp_list.append('na')
        
    except Exception as e:
        print("Unable to perform regex search with error: " + str(e))
    
    else:
        build_dataframe()

#Write lists to dataframe
def build_dataframe():
    try:
        df = pd.DataFrame({'Time Stamp': timestamp_list,
                            'Month': month_list, 
                            'Day': day_list, 
                            'Time': time_list, 
                            'Device': device_list, 
                            'Service': service_list,
                            'Message': message_list, 
                            'Status': status_list, 
                            "UFW Rule": ufwrule_list,
                            'Source': source_list,
                            'Destination': destination_list,
                            'Input': input_list, 
                            'Physical Input': physinput_list,
                            'Output': output_list, 
                            'Physical Output': physoutput_list ,
                            'MAC Address': macaddress_list,
                            'Packet Length': length_list,
                            'Type Of Service': tos_list, 
                            'Precedence': precedence_list, 
                            'Time To Live': ttl_list, 
                            'ID': id_list, 
                            'Flag': flag_list, 
                            'Protocol': protocol_list, 
                            'Source Port': sourceport_list, 
                            'Destination Port': destinationport_list, 
                            'Received Sequence Number': recseq_list, 
                            'Acknowledgment Sequence Number': ackseq_list,
                            'Window': window_list, 
                            'Reserved': reserved_list, 
                            'SYNURGP': synurgp_list 
                            })
    except Exception as e:
        print("Unable to build dataframe with error: " + str(e))
    else:
        print("Succesfully built dataframe")    
        replace_missing_value(df)

#Replace na with NaN
def replace_missing_value(df):
    try:
        df.replace('na', np.nan, inplace=True)
    except Exception as e:
        print("Unable to build replace missing values with error: " + str(e))
    else:
        print("Succesfully replaced missing values")
        save_to_csv(df)
    
#Save to CSV
def save_to_csv(df):
    try:
        out_path_fn = input("Enter full path and file extension of new csv: ")
        df.to_csv('{0}'.format(out_path_fn), index = False)
    except Exception as e:
        print("Unable to save dataframe to csv with error: " + str(e))
    else:
        print("Succesfully saved dataframe to csv")


open_archive()

