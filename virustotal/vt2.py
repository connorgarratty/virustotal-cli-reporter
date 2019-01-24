import requests
import json
import os

def saveChanges(dataList):
	output_file = open('data.txt', 'w')
	json.dump(dataList, output_file, indent=2)
	output_file.close()

try:
	input_file = open('data.txt', 'r')
	data = json.load(input_file)
	input_file.close()
except:
	data = []


pAPIkey = input('\nTo begin, please write your VirusTotal API key: ')

print('\n' + 20*'*' + ' VirusTotal CLI Scanner ' + 20*'*')
while True:
	print('\nChoose [s]can, [r]eport, [d]elete, [l]ist [v]iew report or [q]uit')
	choice = input('> ')
#####################################################################################
	if choice == 's':
		malFile = input('Enter file name (same directory): ')
		while True:
			url = 'https://www.virustotal.com/vtapi/v2/file/scan'

			params = {'apikey': pAPIkey}

			files = {'file': (malFile, open(malFile, 'rb'))}

			response = requests.post(url, files=files, params=params)

			f = open('temp.txt', 'w')
			f.write(str(json.dumps(response.json(), indent=2, sort_keys=True)))
			f.close()
			f = open('temp.txt', 'r')
			temp = json.load(f)
			f.close()
			malHash = temp['md5']
			link = temp["permalink"]
			status = temp['verbose_msg']
			print('\n' + status)
			os.remove("temp.txt")
			break

		scan_library = {
		'malName': malFile,
		'malMD5': malHash,
		'permalink': link
		}
		data.append(scan_library)
		saveChanges(data)
		print('\nScan saved to library.')
#####################################################################################
	elif choice == 'r':
		malHash = input('Enter MD5 from previously scanned file (Check list): ')
		while True:
			url = 'https://www.virustotal.com/vtapi/v2/file/report'

			params = {'apikey': pAPIkey, 'resource': malHash}

			response = requests.get(url, params=params)

			unique_filename = str(malHash + '.txt')
			f = open(unique_filename, 'w')
			f.write(str(json.dumps(response.json(), indent=2, sort_keys=True)))
			f.close()

			status = response.json()['verbose_msg']
			if status == 'Scan finished, information embedded':
				print('\nScan finished. Report log has been saved as ' + unique_filename)
			elif status == 'Your resource is queued for analysis':
				print(status)
			else:
				print('\nScan error, please try again.')
			break
#####################################################################################
	elif choice == 'd':
		if len(data) > 0:
			scan_number = input('Question number to delete: ')
			scan_number = int(scan_number)
			if 0 <= scan_number <= len(data) - 1:
				del data[scan_number]
				saveChanges(data)
				print('\nScan deleted.')
			else:
				print('\nInvalid index number.')
		else:
			print('\nThere are no scans saved.')
#####################################################################################
	elif choice == 'l':
		if len(data) > 0:
			print('   Name ' + 6*'-' + ' MD5')
			for index, item in enumerate(data):
				print(str(index) + ') ' + item['malName'] + ' - ' + item['malMD5'])
		else:
			print('\nThere are no saved scans.')
#####################################################################################
	elif choice == 'v':
		if len(data) > 0:
			print('   Name ' + 6*'-' + ' MD5')
			for index, item in enumerate(data):
				print(str(index) + ') ' + item['malName'] + ' - ' + item['malMD5'])
			if len(data) > 0:
				scan_number = int(input('\nScan number to view: '))
				if 0 <= scan_number <= len(data) - 1:
					scans = data[scan_number]
					rip = open(scans['malMD5'] + '.txt')
					unni = json.load(rip)
					rip.close()
					print('\nName: ' + scans['malName'])
					print('MD5: ' + scans['malMD5'])
					print('SHA1: ' + unni['sha1'])
					print('SHA256: ' + unni['sha256'])
					print('Positives: ' + str(unni['positives']))
					print('Scan date: ' + str(unni['scan_date']))
					print('Total scans: ' + str(unni['total']))
					print('Link: ' + unni['permalink'])
					if unni['positives'] > 0:
						malview = input('Would you like to view which antivirus flagged the file? (Y/N): ')
						malview.lower()
						if malview == 'y':
							for antivirus in unni['scans']:
								if unni['scans'][antivirus]['detected'] == True:
									print('Antivirus: ' + antivirus)
									print('Result: ' + str(unni['scans'][antivirus]['result']))
									print('Version: ' + str(unni['scans'][antivirus]['version']))
									print(20*'#')

				else:
					print('Invalid index number.')
		else:
			print('\nThere are no saved scans.')
#####################################################################################
	elif choice == 'q':
		print('\nSession closed.')
		break

	else:
		print('\nInvalid choice.')