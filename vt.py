import requests
import time
import os
import json

VT_API_KEY = os.getenv('VT_API_KEY')

url = 'https://www.virustotal.com/api/v3/files'
headers = {
    'x-apikey': VT_API_KEY
}


def scan_files():
    print("Scanning files in the output directory...")
    res = []
    for file in os.listdir('output'):
        file_path = os.path.join('output', file)
        if os.path.isfile(file_path) and file_path.endswith('.exe'):
            print(f"Scanning {file_path}...")
            analysis_id = send_file_to_virustotal(file_path)
            result = get_analysis_result(analysis_id)
            
            # convert result to JSON
            result_json = json.dumps(result, indent=2)

            # write result to file
            with open(f"{file_path}.json", 'w') as json_file:
                json_file.write(result_json)

            stats = result['data']['attributes']['stats']
            malicious = stats['malicious']

            s = "{}: {}".format(file, malicious)
            print("  Result: " + s)
            res.append(s)
        
    # write res to file
    print("Writing all results to output/scan_results.txt") 
    with open('output/scan_results.txt', 'w') as f:
        for item in res:
            f.write("%s\n" % item)


# returns: analysis_id
def send_file_to_virustotal(file_path) -> str:
    with open(file_path, 'rb') as f:
        files = {'file': (file_path, f)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        #print(f"Submitted. Analysis ID: {analysis_id}")
        return analysis_id
    else:
        print(f"Failed to submit: {response.status_code} - {response.text}")
        return None



def get_analysis_result(analysis_id: str):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            status = json_response['data']['attributes']['status']
            if status == 'completed':
                stats = json_response['data']['attributes']['stats']
                #print("Analysis complete!")
                #print("Malicious:", stats['malicious'])
                #print("Suspicious:", stats['suspicious'])
                #print("Undetected:", stats['undetected'])
                #print("Harmless:", stats['harmless'])
                return json_response
                break
            else:
                #print("Analysis in progress...")
                time.sleep(3)
        else:
            print("Error retrieving analysis.")
            print(f"Status code: {response.status_code}")
            print(f"Response: {response.text}")

            return None
    

# Use analysis_id from upload step
#get_analysis_result(analysis_id)