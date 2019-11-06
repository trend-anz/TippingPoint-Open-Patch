import os
import sys
import csv
import json
import xml.etree.ElementTree as ET
from io import StringIO
from .loggers import Loggers

try:
    import requests
except:
    from botocore.vendored import requests


class Tp:
    def __init__(self, app_name, profile_name='', verify_certs=False, console_logger=False,
                 log_file_path='', print_logger=False, log_level='INFO'):

        self.logger = Loggers(app_name, console_logger, log_file_path, print_logger, log_level)
        self.profile_name = profile_name
        self.verify_certs = verify_certs

        try:
            self.logger.entry('info', 'Obtaining TP API key')
            self.tp_api_key = os.environ['SMS_KEY']

            self.logger.entry('info', 'Obtaining SMS address')
            self.sms_address = os.environ['SMS_API_ADDRESS']
            self.headers = {'X-SMS-API-KEY': self.tp_api_key}

        except KeyError:
            self.logger.entry('critical', 'Error: "SMS_KEY" and/or "SMS_API_ADDRESS" environment variables are not '
                                          'set. Please set them and try again.')
            sys.exit(1)

        self.logger.entry('info', f'Obtained DS address: {self.sms_address}')

    def get_data_dictionary(self, table_name='', output_format='csv'):
        params = {'method': 'DataDictionary'}

        if output_format:
            params['format'] = output_format

        if table_name:
            params['table'] = table_name

        url = f'https://{self.sms_address}/dbAccess/tptDBServlet'
        response = requests.get(url, headers=self.headers, verify=self.verify_certs, params=params)
        self._check_api_response(response)

        return response.text

    def get_filter_entries(self, filter_nums):
        data = ET.Element('getFilters')
        name = ET.SubElement(data, 'profile')
        name.set('name', self.profile_name)

        for filter_num in filter_nums:
            filter_section = ET.SubElement(data, 'filter')
            number = ET.SubElement(filter_section, 'number')
            number.text = str(filter_num)

        xml_data = ET.tostring(data)
        post_data = {'file': ('get_filter.xml', xml_data)}
        url = f'https://{self.sms_address}/ipsProfileMgmt/getFilters'

        response = requests.post(url, headers=self.headers, verify=self.verify_certs, files=post_data)
        self._check_api_response(response)

        return response.text

    @staticmethod
    def create_map(key_name, table_output):
        '''Iterates through table output. Searches for `key_name`'s value and creates a new dict with the value as
        the key

        Example format:

            '43756': {'BUGTRAQ_ID': '',
                'CLASS': '',
                  'CVE_ID': '',
                  'DESCRIPTION': 'This filter detects ...',
                  'ID': '00000001-0001-0001-0001-000000043756',
                  'MESSAGE': '43756: ISAKMP: Internet...,
                  'NAME': '43756: ISAKMP: Internet Key '
                          'Exchange Version 1 (IKEv1) '
                          'Security Association '
                          'Payload',
                  'NUM': '43756',
                  'PRODUCT_CATEGORY_ID': '1',
                  'PROTOCOL': 'udp',
                  'SEVERITY_ID': '1',
                  'TAXONOMY_ID': '83825558'},
        '''

        output = dict()

        split_output = table_output.split('\n')
        csv_output = csv.DictReader(split_output)

        for row in csv_output:
            row_dict = dict(row)
            new_key = row_dict[key_name]

            output[new_key] = row_dict

        return output

    def get_filter_num_map(self):
        self.logger.entry('info', 'Retrieving SIGNATURE table')
        table_output = self.get_data_dictionary(table_name='SIGNATURE', output_format='csv')
        self.logger.entry('info', 'Converting SIGNATURE table into a filter number map')
        filter_map = self.create_map('NUM', table_output)

        return filter_map

    def get_cve_filter_map(self):
        '''Creates an CVE to filter map.

        Example format:
            'CVE-2019-9978': [{'BUGTRAQ_ID': '',
                    'CLASS': '',
                    'CVE_ID': 'CVE-2019-9978',
                    'DESCRIPTION': 'This filter detects an attempt to use of...'
                    'ID': '00000001-0001-0001-0001-000000035137',
                    'MESSAGE': '35137: HTTP: WordPress Social Warfare Plugin Usage',
                    'NAME': '35137: HTTP: WordPress Social Warfare Plugin Usage',
                    'NUM': '35137',
                    'PRODUCT_CATEGORY_ID': '1',
                    'PROTOCOL': 'http',
                    'SEVERITY_ID': '2',
                    'TAXONOMY_ID': '67439613'}]
            '''
        filter_num_map = self.get_filter_num_map()

        self.logger.entry('info', 'Creating CVE to filter number map')
        cve_map = dict()

        for filter_num, filter_details in filter_num_map.items():
            cves = filter_details['CVE_ID']
            if not cves:
                continue

            split_cves = cves.split(',')

            for cve in split_cves:
                # add cve to map if it doesn't already exist
                if not cve_map.get(cve):
                    cve_map[cve] = []

                cve_map[cve].append(filter_num_map[filter_num])

        return cve_map

    def get_filter_statuses(self, filter_nums):
        self.logger.entry('info', 'Checking the status of filters...')
        filter_data = self.get_filter_entries(filter_nums)

        file_data = StringIO()
        file_data.write(filter_data)
        file_data.seek(0)

        root = ET.parse(file_data)
        for entry in root.findall('filter'):
            filter_name = entry.find('name').text
            filter_status = entry.find('enabled').text

            self.logger.entry('info', f'Status: {filter_status} - Filter: {filter_name}')

    def set_filter_entries(self, filter_nums, enable_filters=True, action_set_option='Block + Notify'):
        filter_setting = 'Enabling' if enable_filters else 'Disabling'

        self.logger.entry('info', f'{filter_setting} filters...')

        data = ET.Element('setFilters')
        name = ET.SubElement(data, 'profile')

        for filter_num in filter_nums:
            filter_section = ET.SubElement(data, 'filter')
            name.set('name', self.profile_name)

            number = ET.SubElement(filter_section, 'number')
            number.text = str(filter_num)

            if enable_filters:
                action_set = ET.SubElement(filter_section, 'actionset')
                action_set.set('name', action_set_option)

            else:
                enabled = ET.SubElement(filter_section, 'enabled')
                enabled.text = 'false'

        xml_data = ET.tostring(data)

        post_data = {'file': ('set_filter.xml', xml_data)}
        url = f'https://{self.sms_address}/ipsProfileMgmt/setFilters'

        response = requests.post(url, headers=self.headers, verify=self.verify_certs, files=post_data)
        self._check_api_response(response)

        return response.text

    def distribute_profile(self, segment_group_name):
        self.logger.entry('info', f'Distributing {self.profile_name} profile to {segment_group_name} segment group')
        params = {
            'profileName': self.profile_name,
            'segmentGroupName': segment_group_name,
        }

        url = f'https://{self.sms_address}/ipsProfileMgmt/distributeProfile'

        response = requests.get(url, headers=self.headers, verify=self.verify_certs, params=params)
        self._check_api_response(response)

        return response

    def json_response(self, status_code, msg):
        output = {
            'statusCode': status_code,
            'body': json.dumps(msg)

        }

        json_output = json.dumps(output)
        self.logger.entry('info', f'Returning the output:\n{json_output}')

        return json_output

    @staticmethod
    def _check_api_response(response):
        if response.status_code != 200:
            raise ValueError(f'API called returned status code {response.status_code} - {response.text}')
