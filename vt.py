import requests
import time


API_KEY = ''

url = 'https://www.virustotal.com/api/v3/files'
headers = {
    'x-apikey': API_KEY
}


# returns: analysis_id
def send_file_to_virustotal(file_path) -> str:
    with open(file_path, 'rb') as f:
        files = {'file': (file_path, f)}
        response = requests.post(url, headers=headers, files=files)

    if response.status_code == 200:
        result = response.json()
        analysis_id = result['data']['id']
        print(f"Submitted. Analysis ID: {analysis_id}")
    else:
        print(f"Failed to submit: {response.status_code} - {response.text}")



def get_analysis_result(analysis_id: str):
    url = f'https://www.virustotal.com/api/v3/analyses/{analysis_id}'
    while True:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_response = response.json()
            status = json_response['data']['attributes']['status']
            if status == 'completed':
                stats = json_response['data']['attributes']['stats']
                print("Analysis complete!")
                print("Malicious:", stats['malicious'])
                print("Suspicious:", stats['suspicious'])
                print("Undetected:", stats['undetected'])
                print("Harmless:", stats['harmless'])
                break
            else:
                print("Analysis in progress...")
                time.sleep(5)
        else:
            print("Error retrieving analysis.")
            break

# Use analysis_id from upload step
#get_analysis_result(analysis_id)