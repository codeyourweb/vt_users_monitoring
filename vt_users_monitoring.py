from doctest import OutputChecker
import requests
import yaml
import csv
import re
import time
import datetime
import os

##
## VIRUSTOTAL RAW API ENDPOINTS 
##
  
# use virustotal api to get the last 80 comments from a user
def _get_raw_vt_user_comments(api_key:str,user_id:str):
    url = 'https://www.virustotal.com/api/v3/users/{id}/comments?limit=40'.format(id=user_id)

    resA = requests.get(url, headers={"Accept": "application/json", "x-apikey": api_key})
    if resA.status_code != 200:
        return

    resB = requests.get(resA.json()['links']['next'], headers={"Accept": "application/json", "x-apikey": api_key})
    if resA.status_code != 200:
        return resA.json().json()

    return resA.json()['data'] + resB.json()['data']

# use virustotal api to get file details based on its identifier 
def _get_raw_vt_file_details(api_key:str, file_id:str):
    url = 'https://www.virustotal.com/api/v3/files/{id}'.format(id=file_id)

    response = requests.get(url, headers={"Accept": "application/json", "x-apikey": api_key})
    if response.status_code != 200:
        return

    return response.json()['data']

##
## CONFIG AND UTILITIES 
##

# read users monitoring yaml configuration file
def read_yaml_configuration(configPath:str):
    with open(configPath) as stream:
        try:
            return yaml.safe_load(stream)
        except yaml.YAMLError as exc:
            return

# write match in csv file
def write_csv_file_match_results(csvFile:str, fileObject):
    fileExists = os.path.isfile(csvFile)

    with open(file=csvFile, mode='a+', newline='', encoding='utf-8') as f:
        writer = csv.writer(f, quoting=csv.QUOTE_ALL, quotechar='"')
        if not fileExists:
            writer.writerow(['md5', 'sha1', 'sha256', 'malicious_scoring', 'first_submission', 'times_submitted', 'in_user_comments', 'match_details', 'virustotal_url'])
        writer.writerow([fileObject['attributes']['md5'], fileObject['attributes']['sha1'],fileObject['attributes']['sha256'], fileObject['attributes']['last_analysis_stats']['malicious'], fileObject['attributes']['first_submission_date'], fileObject['attributes']['times_submitted'], fileObject['user'], fileObject['output'], fileObject['links']['self']])

# return filtered file list from user comments over the last 2 minutes with optional text filters 
def filter_vt_user_comments(user, comments, filters, output_regex):
    filtered_comments = []

    ts = int(time.time()) 
    for comment in comments:
        if comment['attributes']['date'] > ts - 60 * 2 and comment['id'][0:2] == "f-":

            o = {}
            o['user'] = user
            o["hash"] = comment['id'][2:66]
            o['output'] = ''

            re_pattern = re.compile(output_regex)  
            r = re_pattern.findall(comment['attributes']['text'])
            if len(r) > 0:
                o['output'] = r[0]
            
            if len(filters) > 0:
                for f in filters:
                    if f in comment['attributes']['text']:
                        filtered_comments.append(o)
            else:
                filtered_comments.append(o)

    return filtered_comments

def main():
    # config file parsing
    config = read_yaml_configuration('./users_monitoring.yaml')
    if config is None or len(config) == 0:
        print("Error parsing configuration file")
        exit(1)

    file_objects_list = []

    while True:
        # file objects list history cleanup
        if len(file_objects_list) > 1000:
            file_objects_list = file_objects_list[100:]

        # users comments listener
        for configObj in config['users_monitoring']['listener']:
            raw_comments_data = _get_raw_vt_user_comments(config['users_monitoring']['vt_api_key'], configObj['user'])
            if raw_comments_data is None or len(raw_comments_data) == 0:
                print("Error retrieving users comments details - VT API rates excessed or unknown user "+ configObj['user'])
                break
    
            # for each comment: output match on csv file
            for fileObj in filter_vt_user_comments(configObj['user'], raw_comments_data, configObj['filters'], configObj['output_comment_regex']):
                if fileObj["hash"] not in file_objects_list:
                    file_objects_list.append(fileObj["hash"])
                    print('New file in {} user\'s comments: {}'.format(fileObj['user'],fileObj['hash']))

                    # output result
                    fileDetails = _get_raw_vt_file_details(config['users_monitoring']['vt_api_key'], fileObj["hash"])
                    if fileDetails is None or len(fileDetails) == 0:
                        print("Error retrieving file details - API rate maybe excessed")
                        break

                    fileDetails['attributes']['first_submission_date'] = datetime.datetime.fromtimestamp(fileDetails['attributes']['first_submission_date']).strftime('%Y-%m-%d %H:%M:%S')
                    fileDetails['user'] = fileObj['user']
                    fileDetails['output'] = fileObj['output']

                    write_csv_file_match_results("vt-users_monitoring-{}.csv".format(datetime.datetime.now().strftime("%Y-%m-%d_%H")), fileDetails)

        # loop every minute
        time.sleep(60)



if __name__ == '__main__':
    main()
	