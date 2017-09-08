from flask import Flask

import ConfigParser

cf = ConfigParser.ConfigParser()
cf.read("test.conf")

app = Flask(__name__)
@app.route("/")
def hello():    
    return "Hello World!"
@app.route("/aaa")
def haha():
	return cf.get("db","db_port")
 
if __name__ == "__main__":
    app.run()
