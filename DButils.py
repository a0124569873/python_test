import MySQLdb

class DButils():

	con = None

	def __init__(self,conf):
		self.con = MySQLdb.connect(conf["mysql_server"],conf["username"],conf["password"],conf["db_name"])

	def get_con(self):
		return self.con

	def set_dev_conf(self,detect_cycle,black_effect_time,white_effect_time):
		cursor = self.con.cursor()
		sql_cyc = "UPDATE device_conf SET conf_value = '%s' + 1 WHERE type = '%s'" % (detect_cycle,'attack_cyc')
		sql_w = "UPDATE device_conf SET conf_value = '%s' + 1 WHERE type = '%s'" % (black_effect_time,'wlist_time')
		sql_b = "UPDATE device_conf SET conf_value = '%s' + 1 WHERE type = '%s'" % (white_effect_time,'blist_time')
		cursor.execute(sql_cyc)
		cursor.execute(sql_w)
		cursor.execute(sql_b)
		try:
			self.con.commit()
		except:
			self.con.rollback()

	def set_bw_list(self,bw_list):
		cursor = self.con.cursor()

		#clear_table
		clear_sql = "truncate table bwlist"
		cursor.execute(clear_sql)
		try:
			self.con.commit()
		except:
			self.con.rollback()

		sql_list = []

		for each_black_list in bw_list["black"]:
			en_sure("dport",each_black_list)
			en_sure("dstip",each_black_list)
			sql = "insert into bwlist (type,srcip,dstip,dport) values ('%s','%s','%s','%s')"%("b",each_black_list["srcip"],each_black_list["dstip"],each_black_list["dport"])
			sql_list.append(sql)

		for each_black_list in bw_list["white"]:
			en_sure("dport",each_black_list)
			en_sure("dstip",each_black_list)
			sql = "insert into bwlist (type,srcip,dstip,dport) values ('%s','%s','%s','%s')"%("w",each_black_list["srcip"],each_black_list["dstip"],each_black_list["dport"])
			sql_list.append(sql)
		for each_sql in sql_list:
			cursor.execute(each_sql)
		try:
			self.con.commit()
		except:
			self.con.rollback()

	def set_limit(self,limite_list):

		cursor = self.con.cursor()

		#clear_table
		clear_sql = "truncate table threshold_value"
		cursor.execute(clear_sql)
		try:
			self.con.commit()
		except:
			self.con.rollback()

		sql_list = []

		for each_limite in limite_list:
			sql = "insert into threshold_value (ip,port,syn,udp) values ('%s','%s','%s','%s')"%(each_limite["ip"],each_limite["port"],each_limite["syn"],each_limite["udp"])
			sql_list.append(sql)

		for each_sql in sql_list:
			cursor.execute(each_sql)
		try:
			self.con.commit()
		except:
			self.con.rollback()

def en_sure(key,d_list):
	if key not in d_list.keys():
		d_list[key] = ""