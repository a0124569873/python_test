import urllib2
import urllib
def postHttp():
    url="http://192.168.16.186/zk/hd_node/index.php"
    postdata=dict(type="restart")
    postdata=urllib.urlencode(postdata)
    request = urllib2.Request(url,postdata)
    response=urllib2.urlopen(request)
    print response.read()

postHttp()
