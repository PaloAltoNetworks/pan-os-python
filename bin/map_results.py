import sys, os, gzip, csv, time, traceback
import sys,splunk.Intersplunk
import traceback
		
#TODO App should be determined by search that calls the script
map_type = "threat"
log = open(os.path.join(os.environ["SPLUNK_HOME"], 'var', 'log', 'splunk','ammap_map_results.log'), 'a')   
results_file = ""
result_path = os.path.join(os.environ["SPLUNK_HOME"], 'var', 'run', 'splunk','dispatch')
DEBUG = 1
zoom_string = ' zoom="399.8812%" zoom_x="-33.8%" zoom_y="-142.62%" ' 


def get_results():
	global outputFile
	global app
	global zoom
	if len(sys.argv)>5:
		logger("INFO - Alert Action Suspected!")
		results = sys.argv[6]
		path = results[results.find('sid=')+4:]
		results_file = os.path.join(result_path,path,'results.csv.gz')
		
		logger("INFO - Alert Action Fired...Moving On")
	elif len(sys.argv) == 2:
		logger("INFO - checking for SID: "+ sys.argv[1])

		results_file =  os.path.join(results_file,sys.argv[1],'results.csv.gz')

		logger("INFO - SID found....Moving On")
	elif sys.argv.count('-f')>0:
		logger("INFO - Attempting to read from local file: "+ sys.argv[2])
		results_file = sys.argv[2]
		logger("INFO - File found....Moving On")
	else:
		logger("INFO - Checking Intersplunk for results")
		results,dummyresults,settings = splunk.Intersplunk.getOrganizedResults()
		
		result_dict_list = []
		logger("INFO - checking for target app in search results")
		if results[0].has_key("app"):
			app  = results[0]["app"]
		logger("INFO - checking for output file in search results")
		if results[0].has_key("output_file"):
			outputFile  = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', app,'appserver','static','xml_out',results[0]["output_file"])
		logger("INFO - checking for zoom settings in search results")
		if results[0].has_key("zoom"):
			zoom  = results[0]["zoom"]
		else:
			zoom = zoom_string




		return results
	results = csv.reader(gzip.open(results_file),delimiter=',', quotechar='"')
	logger("INFO - Results Recieved, constructing dict")
	header = []
	resultDict = {}
	result_dict_list = []
	first = 1

	for row in results:
		if first:
			header = row
			logger("FOUND FIELDS: "+str(row)) 
			first = 0	
			continue;
		resultDict = {}
		x = 0	
		for col in row:
			resultDict[header[x]] = col
			x = x + 1 
		result_dict_list.append(resultDict)
	logger("checking for target app in search results")
	if result_dict_list[0].has_key("app"):
		app  = result_dict_list[0]["app"]

	logger("checking for output file in search results")
	if result_dict_list[0].has_key("output_file"):
		outputFile = os.path.join(os.environ["SPLUNK_HOME"], 'etc', 'apps', app,'appserver','static','xml_out',result_dict_list[0]["output_file"])

	if result_dict_list[0].has_key("zoom"):
		zoom  = result_dict_list[0]["zoom"]

	else:
		zoom = zoom_string




	return result_dict_list


def aggregate_results(result_dict_list): 
	logger("INFO - Aggregating results ....")
	iterator = result_dict_list[0]["iterator"]
	geo_dict = {}
	for dict in result_dict_list:
## Need to crate a unique key to calculate totals by location. 
		key = dict["client_lon"]+dict["client_lat"]
		if geo_dict.has_key(key) == False:
			geo_dict[key] = {'iterator':iterator,'uniq':{dict[iterator]:1},'count':int(dict["count"]),iterator:[dict[iterator]],"city":dict["client_city"],"region":dict["client_region"],"country":dict["client_country"],"long":dict["client_lon"],"lat":dict["client_lat"],"label":dict["iterator_label"],"movie_color":dict["movie_color"],"title":dict["count_label"]} 	
		else:
#			logger("Repeat Key updating iterator list and count for:" + key)
			geo_dict[key]['count'] = geo_dict[key]['count'] + int(dict["count"])
			geo_dict[key][iterator].append(dict[iterator])
			if geo_dict[key]['uniq'].has_key(dict[iterator]):
				continue;
			else:
				geo_dict[key]['uniq'][dict[iterator]] = 1
	return geo_dict

def format_movies(geo_results):
	movie_list = []
	for key in geo_results.keys():
		movie = ""
		title = ""
		url = "/app/"+app+"/flashtimeline?q=search%20"
		if len(geo_results[key]["country"])>1:
			title = geo_results[key]["country"]
		if len(geo_results[key]["region"])>1:
			title = geo_results[key]["region"]+", "+ title 
		if len(geo_results[key]["city"])>1:
			title = geo_results[key]["city"]+", "+ title 
		title = title + '\n ' + geo_results[key]["title"] + '(s): ' + str(geo_results[key]["count"]) + "\n Unique " +geo_results[key]["label"] + "(s): "+ str(len(geo_results[key]["uniq"])) + '"'
		uniq_keys = ""
		for x in geo_results[key]["uniq"].keys():
			uniq_keys = uniq_keys + geo_results[key]["iterator"] + "%3D" + x + "%20OR%20"   
		url = url + uniq_keys[:len(uniq_keys)-8]		
		size = int(geo_results[key]["count"]) / 10
 		if size>15: size = 25
		if size==15: size = 25
 		if size<2: size = 10
 		if size==2: size=10
		movie = '\n<movie url="'+url+'" target="_parent" fixed_size="true" file="circle" alpha="60" title="&lt;b&gt; '
		movie = movie + title + '\n lat="'+geo_results[key]["lat"]+'" long="'+geo_results[key]["long"]+'" height="'+str(size)+'" width="'+str(size)+'" color="'+geo_results[key]["movie_color"]+'">\n</movie>\n' 
		movie_list.append(movie)
	return movie_list

def write_threat_xml(movies):

	movies_string = ""
	for movie in movies:
		movies_string = movie + '\n' + movies_string 
	end = '''
  <labels>
    <label x="0" y="50" width="100%" align="center" text_size="16" color="#FFFFFF">
      <text><![CDATA[]]></text>
      <description><![CDATA[]]></description>
    </label>
  </labels>  
</map>
		'''

	borders = '''
	
	  <areas> 

      <area title="borders" mc_name="borders" color="#FFFFFF" balloon="false"></area>

  </areas>
  
  '''
	xml_out =  '<map map_file="maps/world.swf" tl_long="-168.5" tl_lat="83.50" br_long="190" br_lat="-55" '+zoom+' >\n '+borders+'\n\t<movies>\t\n' + movies_string + '</movies></map>'
	xml_file = open(outputFile,'w')
	xml_file.write(xml_out)
	logger("Writing XML to : " + outputFile) 
	return 0


def logger(string):
	if DEBUG==1:
#		print time.asctime() + ' - ' + string
		log.write(time.asctime() + ' - ' + string + "\n")
		return 0
def run():
	try:
		logger( "INFO - get_results()" )
		result_dict_list = get_results()
		logger("INFO - aggregate_results()")
		geo_results = aggregate_results(result_dict_list)
		logger("INFO - format_movies()")
		movies = format_movies(geo_results)
		logger("INFO - write_threat_xml()")
		write_threat_xml(movies)
		print "Map Results Completed"
	except:
		stack =  traceback.format_exc()
		logger('ERROR - Traceback:' + str(stack))
		
run()
