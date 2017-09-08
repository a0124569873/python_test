# coding=utf-8

import time, os, json, socket

def meminfo():
    meminfo = {}
    with open('/proc/meminfo') as f:
        for line in f:
            meminfo[line.split(':')[0]] = line.split(':')[1].strip()
    return meminfo

def memfree():
    m = meminfo()
    return int(m["MemFree"].split("k")[0])

def memtotal():
    m = meminfo()
    return int(m["MemTotal"].split("k")[0])

def uptime():
    with open('/proc/uptime') as f:
        for line in f:
            return float(line.split(" ")[0])

    return 0

def sys_load():
    with open('/proc/loadavg') as f:
        for line in f:
            return float(line.split(" ")[0])

    return 0

def cpu_usage():
    try:
        with open("/proc/stat", 'r') as f:
            for line in f.readlines():
                l = line.split()
                if len(l) < 5:
                    continue
                if l[0].startswith('cpu'):
                    (user, nice, system, idle, iowait, irq, softirq, stealstolen, guest,x) = l[1:] 
                    total = float(user) + float(nice) + float(system) + float(idle) + float(iowait) + \
                            float(irq) + float(softirq) + float(stealstolen) + float(guest)

                    idle = float(idle)
                    return (total - idle, total);
    except Exception, e:
        print e
        pass
   
    return (0, 0)

def safe_json_load(file):
    try:
        content = "";
        with open(file, 'r') as f:
            for line in f.readlines():
                content += line

        return safe_json_loads(content)
    except Exception, e:
        pass
    finally:
        pass

    return None

def safe_json_loads(content):
    try:
        return json.loads(content)
    except Exception, e:
        pass
    finally:
        pass

    return None

def safe_json_dump(path, data):
    try:
        path = os.path.abspath(path)

        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        with open(path, 'w') as fp:
            json.dump(data, fp, indent=4)
    except Exception, e:
        print e
        pass
    return;

def disk_stat():
    hd={}  
    disk = os.statvfs("/")  
    hd['available'] = disk.f_bsize * disk.f_bavail /1024
    hd['capacity'] = disk.f_bsize * disk.f_blocks /1024
    return hd

def net_data():
    with os.popen("ifconfig -s") as f:
        bk_path = "/tmp/net_info"
        last_info = safe_json_load(bk_path)
        info = {"rx":0, "tx":0, "timestamp":time.time()}
        for line in f.readlines()[1:]:
            l = line.split()
            if l[-1] != "BMRU":
                continue
            
            h = ["Iface", "MTU", "RX-OK", "RX-ERR", "RX-DRP", "RX-OVR", "TX-OK", "TX-ERR", "TX-DRP", "TX-OVR", "Flg"]
            d = dict(zip(h, l))
            info["rx"] += int(d["RX-OK"])
            info["tx"] += int(d["TX-OK"])
        
        safe_json_dump(bk_path, info)

        if last_info and "rx" in last_info and "tx" in last_info and "timestamp" in last_info:
            rx = (info["rx"] - last_info["rx"])/(info["timestamp"] - last_info["timestamp"])
            tx = (info["tx"] - last_info["tx"])/(info["timestamp"] - last_info["timestamp"])

            return {"rx": round(rx, 2), "tx": round(tx, 2)}
        else:
            return {"rx":0, "tx":0}

def extern_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 0))
    return s.getsockname()[0]

cpu = cpu_usage()
disk = disk_stat()
net = net_data()

# ip, time
#print extern_ip(), round(time.time(), 2),

# uptime
#print uptime(),

# cpu
print round(cpu[0]/cpu[1]*100, 2), sys_load(),

# memory
#print memtotal(), memfree(), 

# dist
#print disk["available"], disk["capacity"],

# net
#print net["rx"], net["tx"]
