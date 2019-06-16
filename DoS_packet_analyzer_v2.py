import dpkt
import socket
import datetime

#configuration
server = '10.0.1.1'
http_duration_max = 60
rate_min = 20
interval_long = 4

f = open('challange.pcap', 'rb')
pcap = dpkt.pcap.Reader(f)
streams = {}
for num, (ts, buff) in enumerate(pcap):
	eth = dpkt.ethernet.Ethernet(buff)
	ip = eth.data
	tcp = ip.data
	id = '#%d'%num
	ip_dst = socket.inet_ntoa(ip.dst)
	ip_src = socket.inet_ntoa(ip.src)
	port_dst = tcp.dport
	port_src = tcp.sport
	time = datetime.datetime.utcfromtimestamp(ts)
	syn_flag = ( tcp.flags & dpkt.tcp.TH_SYN ) != 0
	rst_flag = ( tcp.flags & dpkt.tcp.TH_RST ) != 0
	psh_flag = ( tcp.flags & dpkt.tcp.TH_PUSH) != 0
	ack_flag = ( tcp.flags & dpkt.tcp.TH_ACK ) != 0
	fin_flag = ( tcp.flags & dpkt.tcp.TH_FIN ) != 0
	http_body = str(tcp)[str(tcp)[:-3].rfind("\\n"):].replace("\\n","").replace("\\r'","").replace("\\r\"","")
	streamId =  (str(ip_src) + ":" + str(port_src) + ":"+ str(ip_dst)+":"+str(port_dst))
	if ip_dst == server:
		if syn_flag is True:
			streams[streamId] = {"packets":[{"id":id,"time":time,"size":len(http_body),"flags":["SYN"]}]}
		else:
			if streamId in streams.keys():
				flags = []
				if ack_flag is True:
					flags.append('ACK')
				if psh_flag is True:
					flags.append('PSH')
				if fin_flag is True:
					flags.append('FIN')
				if rst_flag is True:
					flags.append('RST')
				packet = {"id":id,"time":time,"size":len(http_body),"flags":flags}
				streams[streamId]['packets'].append(packet)
f.close()

def packet_interval(stream):
	times = []
	for packets in stream:
		for packet in packets[2:]:
			times.append(packet["time"])

	intervals = []
	for i in range(0,len(times) -1):
		delta = times[i + 1] - times[i]
		a = str(delta).replace("0:00:","")
		interval = round(float(a))
		intervals.append(interval)

	average = sum(intervals) / len(intervals)

	if(len(set(intervals))==1):
		return {"rate":"Fixed", "interval":intervals[0]}
	else:
		return {"rate":"Interchangeable", "interval":average}

def http_req(stream):												#find stream duration
	for packets in stream:
		for packet in packets:
			if 'FIN' in  packet["flags"]:
				is_fin = True
				end = packet["time"]
				break
			else:
				is_fin = False
	for packet in stream:
		start = packet[2]["time"]
		if is_fin == False:
			end = packet[-1]["time"]

	diff = end - start
	return {"fin":is_fin, "duration":diff.seconds}

def byte_rate(stream):												#bytes in HTTP body per packet
	total_size = 0
	for packets in stream:
		for packet in packets[2:]:
			size = packet["size"]
			total_size +=  size

	for packets in stream:
		count = len(packets)

	rate = total_size / count
	return rate

for streamId, stream in streams.items():
	print('TCP stream ' + streamId)
	print('---------')
	for packets in stream:
		stream = stream.values()
		dos_score = 0
		if http_req(stream)["duration"] > http_duration_max:			#trigger detection if connection lasts over the configured time
			dos_score +=1
			if packet_interval(stream)["rate"] == "Fixed":
				dos_score +=1
				print('Suspicious constant rate between packets detected')
			if packet_interval(stream)["interval"] >= interval_long:
				dos_score +=1
				print('Long intervals between packets detected - ' + str(packet_interval(stream)["interval"]) + ' sec/packet' )
			if byte_rate(stream) <= rate_min:
				dos_score +=1
				print("Slow byte rate detected - " + str(round(byte_rate(stream),2)) + ' bytes/packet')
		if dos_score >= 2:
			print("--Slow POST DoS attack detected--")
			print("\n")