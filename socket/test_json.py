import re,json,os

config = {
    "bgp":{
        "server":"192.168.5.32",
        "server_port":12001,
        "add_delay":0,
        "del_delay":5*60
    },
    "common_ip":{
        "pk":100,
        "bytes":500
    },
    "udp":{
        "3a3129adbf94b5e2be9a986f77da5e53":{
            "ip":"10.168.10.198",
            "port":8610,
            "pk":100,
            "bytes":500
        },
        "client_list":{
            "3a3129adbf94b5e2be9a986f77da5e53":{
                "ip":"10.168.10.198",
                "port":8610
            }
        }

    },
    "tcp":{
        "e249e540b9467e509eb75a018d218b56":{
            "ip":"192.168.122.10",
            "port":80,
            "pk":100,
            "bytes":500
        },
        "client_list":{
            "e249e540b9467e509eb75a018d218b56":{
                "ip":"192.168.122.10",
                "port":80
            }
        }
    }
}


def safe_json_load(file, default=None, commit=True):
    try:
        content = "";
        with open(file, 'r') as f:
            for line in f.readlines():
                content += re.sub(r'(//.*?$)', '', line) if commit else line

        # print content
        return safe_json_loads(content, commit)
    except Exception, e:
        pass
    finally:
        pass

    return default


def safe_json_loads(content, default=None, commit=True):
    try:

        # content = re.sub(r'(/\*[\w\W]*?\*/)', '', content) if commit else content

        print content
        print json.loads('{"dfssdf":"dsfdsf"}')
        return json.loads(content)
    except Exception, e:
        pass
    finally:
        pass

    return default

def safe_json_dump(path, data, pretty=False):
    try:
        path = os.path.abspath(path)

        if not os.path.isdir(os.path.dirname(path)):
            os.makedirs(os.path.dirname(path))

        with open(path, 'w') as fp:
            json.dump(data, fp, indent=4 if pretty else None)
    except Exception, e:
        print e
        pass
    return;

path = "/hard_disk/conf/nsc.conf"



safe_json_dump(path,config)

# print safe_json_load(path)