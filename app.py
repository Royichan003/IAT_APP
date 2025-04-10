from flask import Flask, render_template, request, redirect, session,jsonify
import logging
import telnetlib
import pexpect
import sqlite3
import os
import time
import threading
import re
import requests

app = Flask(__name__)
app.secret_key = "akDFJ34mdfsYMH567sdf"
logging.basicConfig(level=logging.DEBUG)

connection_status = {"status": "Not Connected To Device"}
active_connections = {}
DB_NAME = 'sql/iat_app_db.db'
server_data = {
	"user":"",
	"device":"",
	"host": "",
	"port": "",
	"username": "",
	"password": "",
	"login_string":""
}
# List of command templates
command_list=[]
device_list=[]
# Set a timeout for the connection
CONNECTION_TIMEOUT = 60

def timeout_handler(conn):
	global connection_status
	print("Device connection attempt timed out")
	try:
		conn.close()
		connection_status["status"] = "Not Connected To Device"
	except Exception:
		pass

@app.route("/get_status")
def get_status():
	global connection_status
	"""Return the current connection status as JSON."""
	#print("Returing connection status:%s\n"%connection_status["status"])
	return jsonify({"connection_status": connection_status["status"]})


@app.route('/')
def home():
	if 'loggedin' in session:
		return redirect('/home')  # Redirects to /home if logged in
	return redirect('/login')  # Otherwise, redirects to /login

@app.route('/login', methods=['GET', 'POST'])
def login():
	global server_data,device_list
	user = request.form.get('username')
	password = request.form.get('password')
	if user and password:
		conn, cursor = get_db_connection()
		select_query="select id from users where username='%s' and password='%s'"%(user,password)
		cursor.execute(select_query)
		user_data = cursor.fetchone()
		if user_data:
			print("Login credentials varified succesfully\n")
			session['loggedin'] = True
			session['user'] = user
			select_query="select device from device_cmd"
			cursor.execute(select_query)
			result = [row[0] for row in cursor.fetchall()]
			conn.close()
			if result:
				print("device list is available\n")
				device_list = sorted(set(result))
			return render_template('home.html',device_list=device_list)
		else:
			error = 'Invalid Credentials!'
			return render_template('login.html', error=error)
	return render_template('login.html', error='')

@app.route('/home')
def dashboard():
	global device_list
	if 'loggedin' not in session:
		return redirect('/login')  # Prevents direct access to /home without login
	disconnect()
	return render_template('home.html',device_list=device_list)  # Serves home page

@app.route('/logout')
def logout():
	session.clear()
	connection_status["status"]="Not Connected To Device"
	return render_template('login.html', error="") # Redirects to login after logout

@app.route('/downstreams', methods=['GET', 'POST'])
def downstreams():
	global server_data,command_list,connection_status
	server_data.clear()
	if 'loggedin' not in session:
		return redirect('/login')  # Redirect to login if not authenticated
	device_name = request.args.get('device')  # Get device from URL
	print("Received device name:[%s]\n"%device_name)
	get_server_info(session['user'],device_name)
	server_data["device"]=device_name
	return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="",connection_status=connection_status["status"],**server_data)

@app.route('/execute_command', methods=['POST'])
def execute_command():
	global active_connections,device_list,server_data,command_list,connection_status
	if 'loggedin' not in session:
		return redirect('/home')
	command = request.form.get("command_input")
	http_method=request.form.get("http_method")
	http_url=request.form.get("http_url")
	output=""
	print("Received command: %s active_connection:%s\n" %(command,active_connections))
	if "telnet" in active_connections:
		tn = active_connections["telnet"]
		time.sleep(0.5)
		tn.read_very_eager()  # Clear any leftover data
		tn.write(command.encode("ascii") + b"\n")
		time.sleep(0.5)
		output = tn.read_very_eager().decode("utf-8").strip()
	elif "ssh" in active_connections:
		ssh = active_connections["ssh"]
		#Flush the buffer** before sending the command
		while True:
			try:
				ssh.read_nonblocking(size=4096, timeout=0.5)  # Clear any remaining buffer
			except pexpect.exceptions.TIMEOUT:
				break  # No more buffer to clear
		time.sleep(0.5)
		#ssh.read()
		ssh.sendline(command)
		time.sleep(0.5)
		ssh.expect([".*[#\$>]"])
		output=ssh.after.decode().strip()
		output=output.split("\n")
		output = "\n".join(output[1:])
	elif "http" in active_connections:
		if not http_method and not http_url:
			print("http_method and http_url required\n")
			return render_template('downstreams.html',command_list=command_list,edit_mode=False, result=output,connection_status=connection_status["status"],**server_data)
		print("Received http_method:[%s] http_url:[%s]\n" %(http_method,http_url))
		try:
			if http_method == "GET":
				response = requests.get(http_url)
			elif http_method == "POST":
				response = requests.post(http_url,command)
			elif http_method == "PUT":
				response = requests.put(http_url,command)
			elif http_method == "DELETE":
				response = requests.delete(http_url)
			else:
				print("Unsupported HTTP method:%s\n"%http_method)
			output=response.text
		except Exception as e:
			print("Request failed:%s\n"%str(e))

	print("Output received from downstream:%s\n"%output)
	return render_template('downstreams.html',command_list=command_list,edit_mode=False, result=output,connection_status=connection_status["status"],**server_data)

@app.route('/edit_server', methods=['POST'])
def edit_server():
	global server_data,connection_status
	action = request.form.get("action")

	if action == "edit":
		return render_template('downstreams.html',command_list=command_list,edit_mode=True, result="",connection_status=connection_status["status"],**server_data)
	elif action == "save":
		# Update server details
		server_data["user"] = session["user"]
		server_data["device"] = str(request.form["device"])
		server_data["host"] = str(request.form["host"])
		server_data["port"] = str(request.form["port"])
		server_data["username"] = str(request.form["username"])
		server_data["password"] = str(request.form["password"])
		server_data["login_string"] = str(request.form["login_string"])
		save_server_info(server_data)

		return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="",connection_status=connection_status["status"],**server_data)

@app.route('/connect', methods=['POST'])
def connect():
	global server_data,connection_status,command_list
	# Get form data
	protocol = request.form.get("protocol")
	host = server_data.get("host")
	port = server_data.get("port")
	username = server_data.get("username")
	password = server_data.get("password")
	login_string=server_data.get("login_string")

	re_pass_patt = re.compile(".*password:", re.IGNORECASE)
	re_login_patt = re.compile(".*login:", re.IGNORECASE)
	re_success_patt = re.compile(".*PAGE\s+\d+", re.IGNORECASE)  # Pattern for successful login

	print("Protocol selected:%s\n"%protocol)
	print("Trying to connect to host:[%s] port:[%s] username:[%s] password:[%s] login_string:[%s]\n"%(host,port,username,password,login_string))
	if not host or not port:	
		print("Server details not available to connect\n")
		return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="",connection_status=connection_status["status"],**server_data)
	if protocol == "TELNET" or protocol == "SSH":
		if not username or not password:
			print("username and password are required to connect\n")
			return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="",connection_status=connection_status["status"],**server_data)
	if protocol == "TELNET":
		try:
			tn = telnetlib.Telnet(host,int(port))
			timer = threading.Timer(CONNECTION_TIMEOUT, timeout_handler, [tn])
			timer.start()
			if login_string:
				print("sending LOGIN string\n")
				tn.write(login_string.encode("ascii") + b"\n")
			else:
				print("login command not available, connecting with username and password\n")
				# Read until the login prompt appears using regex
				output = read_telnet_response(tn)
				if re_login_patt.search(output):
					tn.write(username.encode("ascii") + b"\n")
					print("login prompt received, username sent\n")
				# Read until the password prompt appears using regex
				output = read_telnet_response(tn)
				if re_pass_patt.search(output):
					tn.write(password.encode("ascii") + b"\n")
					print("password prompt received, password sent\n")
					tn.write("vt100\n")  # Respond with a known terminal type
					output = read_telnet_response(tn)
				output = read_telnet_response(tn)
			if "RESP:0" in output or "SUCCESS" in output or re_success_patt.search(output):
				active_connections['telnet'] = tn
				connection_status["status"] = "Connected to Device"
				print("Telnet connection established to %s:%s"%(host, port))
		except Exception as e:
			print("Telnet connection failed:%s"%(str(e)))
	elif protocol == "SSH":
		try:
			# Start an interactive SSH session
			ssh_command = "ssh %s@%s"%(username,host)
			if login_string:
				ssh_command = "ssh %s@%s -p %s"%(username,host,port)
			print("Sending ssh command:[%s]\n"%ssh_command)
			child = pexpect.spawn(ssh_command, timeout=CONNECTION_TIMEOUT)
			timer = threading.Timer(CONNECTION_TIMEOUT, timeout_handler, [child])
			timer.start()
			# Expect password prompt, timeout, or EOF
			got = child.expect([re_pass_patt, pexpect.TIMEOUT, pexpect.EOF])
			print("SSH got:[%s]\n"%got)
			if got == 0:  # Matched the password prompt using regex
				child.sendline(password)
			elif got == 1:  # Timeout occurred
				print("Connection Timed Out")
				child.close()
			elif got == 2:  # Connection closed unexpectedly
				child.close()
			active_connections['ssh'] = child
			connection_status["status"] = "Connected to Device"
			print("SSH connection established to %s:%s"%(host, port))
		except Exception as e:
			print("SSH connection failed:%s\n"%(str(e)))

	elif protocol == "HTTP":
			tn = telnetlib.Telnet(host,int(port))
			timer = threading.Timer(CONNECTION_TIMEOUT, timeout_handler, [tn])
			timer.start()
			active_connections['http'] = tn
			connection_status["status"] = "Connected to Device"
			print("HTTP connection established to %s:%s"%(host, port))
	
	return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="",connection_status=connection_status["status"],selected_protocol=protocol,**server_data)

def read_telnet_response(tn):
	output = []
	while True:
		try:
			line = tn.read_until(b"\n", timeout=.5).decode("utf-8").strip()
			if not line:  # Stop if no more data
				break
			output.append(line)
		except EOFError:
			break  # Stop if the connection closes
	output = "\n".join(output)
	print("read_telnet_response: output:[%s]\n"%output)
	return output

@app.route('/disconnect', methods=['POST'])
def disconnect():
	global server_data,connection_status,command_list
	connection_status["status"] = "Not Connected To Device"
	if "telnet" in active_connections:
		active_connections["telnet"].close()
		del active_connections["telnet"]
		print("Telnet connection closed.\n")

	if "ssh" in active_connections:
		active_connections["ssh"].close()
		del active_connections["ssh"]
		print("SSH connection closed.\n")
		if "http" in active_connections:
				active_connections["http"].close()
				del active_connections["http"]
				print("HTTP connection closed.\n")

	return render_template('downstreams.html',command_list=command_list,edit_mode=False, result="", connection_status=connection_status["status"],**server_data)

def save_server_info(server_data):
	conn, cursor = get_db_connection()
	# Check if user already has a saved server, update it
	select_query="select id,device_id,user_id,host,port,username,password,login_string from server_info where user_id ='%s' and device_id='%s'"%(server_data["user"],server_data["device"])
	print("select_query :[%s]\n"%select_query)
	cursor.execute(select_query)
	existing = cursor.fetchone()

	if existing:
		delete_query="delete from server_info where user_id ='%s' and device_id='%s'"%(server_data["user"],server_data["device"])
		cursor.execute(delete_query)
	insert_query="""insert into server_info(device_id,user_id,host,port,username,password,login_string) 
	values('%s','%s','%s','%s','%s','%s','%s')"""%(server_data["device"],server_data["user"],server_data["host"],server_data["port"],server_data["username"],server_data["password"],server_data["login_string"])
	print("insert_query :[%s]\n"%insert_query)
	cursor.execute(insert_query)
	print("save_server_info: server details added successfully\n")
	conn.commit()
	conn.close()

def get_db_connection():
	"""Creates and returns a database connection."""
	conn = sqlite3.connect(os.path.abspath(DB_NAME))
	conn.row_factory = sqlite3.Row  # Enables dictionary-like row access
	cursor = conn.cursor()
	return conn, cursor

def get_server_info(user,device):
	global server_data,command_list
	conn, cursor = get_db_connection()
	select_query="select id,device_id,user_id,host,port,username,password,login_string from server_info where user_id ='%s' and device_id='%s'"%(user,device)
	cursor.execute(select_query)
	data = cursor.fetchone()
	if data:
		server_data["user"] = data["user_id"]
		server_data["device"] = data["device_id"]
		server_data["host"] = data["host"]
		server_data["port"] = data["port"]
		server_data["username"] = data["username"]
		server_data["password"] = data["password"]
		server_data["login_string"] = data["login_string"]
		print("get_server_info fetched successfully\n")
	select_query="select command from device_cmd where device='%s'"%device
	cursor.execute(select_query)
	command_list = [row[0] for row in cursor.fetchall()]
	conn.close()
	return server_data,command_list

@app.route('/upload', methods=['POST'])
def upload_file():
	global device_list
	upload_folder="uploads"
	"""Handles SQL file upload and executes it."""
	if 'sqlFile' not in request.files:
		print("No file uploaded!\n")

	file = request.files['sqlFile']
	if file.filename == '':
		print("No selected file!\n")

	if file and file.filename.endswith('.sql'):
		print("Uploaded file:%s getting processed\n"%file.filename)
		file_path = os.path.join(upload_folder, file.filename)
		file.save(file_path)
		device_list = execute_sql_file(file_path,"")  # Load data into SQLite
		print("Delice list:%s\n"%device_list)
		# Remove file if already exists
	if os.path.exists(file_path):
		os.remove(file_path)
		print("Uploaded file removed from directory\n")
	return render_template('home.html',device_list=device_list)	

def execute_sql_file(sql_file,new_device):
	"""Executes SQL statements from an uploaded file into SQLite database."""
	try:
		result=[]
		conn, cursor = get_db_connection()
		if sql_file and new_device=="":
			with open(sql_file, 'r') as f:
				sql_script = f.read()
			cursor.executescript(sql_script)  # Executes multiple SQL statements
			print("SQL file executed successfully!\n")
		else:
			insert_query="insert into device_cmd(cmd_key,device,command,cmd_type,description) values('','%s','','','')"%new_device
			cursor.executescript(insert_query)
			print("New device :%s added successfully!\n"%new_device)
		conn.commit()
		delete_dupl_query="delete from device_cmd where rowid not in (select min(rowid) from device_cmd group by cmd_key, device, command, cmd_type, description)"
		cursor.executescript(delete_dupl_query)  # Executes multiple SQL statements
		conn.commit()
		print("Duplicate entries removed from device_cmd\n")
		select_query="select device from device_cmd"
		cursor.execute(select_query)
		result = [row[0] for row in cursor.fetchall()]
		result = sorted(set(result))
		cursor.close()
		conn.close()
	except Exception as e:
		print("Error executing SQL file:%s\n"%str(e))
	
	return result

@app.route('/redirect_home')
def redirect_home():
	# This route redirects to the home page directly
	return redirect('/home')

@app.route('/clear-data', methods=['POST'])
def clear_data():
	global device_list,server_data
	try:
		conn, cursor = get_db_connection()
		delete_device_cmd_query="delete from device_cmd"
		cursor.executescript(delete_device_cmd_query)
		conn.commit()
		delete_server_info_query="delete from server_info"
		cursor.executescript(delete_server_info_query)
		conn.commit()
		device_list=[]
		server_data.clear()
		print("Data cleared successfully!")  # Example action
	except Exception as e:
		print("Failed to clear data:%s\n"%str(e))
	return render_template('home.html',device_list=device_list)

@app.route("/add-device", methods=["POST"])
def add_device():
	global device_list
	new_device = request.form.get("device_name")
	if new_device and new_device not in device_list:
		device_list = execute_sql_file("",new_device)
	else:
		print("Device already exists!\n")

	return render_template('home.html',device_list=device_list)

@app.route('/delete_device', methods=['POST'])
def delete_device():
	global device_list
	device_name = request.form.get('device')
	if device_name in device_list:
		device_list.remove(device_name)
	conn, cursor = get_db_connection()
	delete_device_cmd_query="delete from device_cmd where device='%s'"%device_name
	cursor.executescript(delete_device_cmd_query)
	conn.commit()
	print("Device :%s removed from device list\n"%device_name)
	return render_template('home.html',device_list=device_list)


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=9876, debug=True)






