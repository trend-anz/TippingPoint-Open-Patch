import sys
import warnings
from libs.tp import Tp

if not sys.warnoptions:
    warnings.simplefilter('ignore')

APP_NAME = 'tp'


class Op(Tp):
    def __init__(self, app_name, profile_name, print_logger=False):
        super().__init__(app_name, profile_name, print_logger=print_logger)

        self.logger.entry('info', 'Retrieving profile names')
        profile_table = self.get_data_dictionary('PROFILE')

        self.logger.entry('info', 'Converting PROFILE table data to map')
        profile_map = self.create_map('NAME', profile_table)

        if self.profile_name not in profile_map:
            msg = f'Profile name {self.profile_name} does not exist on SMS {self.sms_address}'
            self.logger.entry('critical', msg)
            sys.exit(1)

    def run(self, cve, segment_group_name, enable_filters):
        enable_filters_bool = self.str_to_bool(enable_filters)

        self.logger.entry('info', f'Received {cve} and profile name {self.profile_name}')

        cve_map = self.get_cve_filter_map()
        cve_filters = cve_map.get(cve)

        if not cve_filters:
            msg = f'Cannot find an IPS filter for {cve}'
            self.logger.entry('critical', msg)
            status = self.json_response(400, msg)

            return status

        filter_nums = [entry['NUM'] for entry in cve_filters]
        joined_filter_nums = ', '.join(filter_nums)

        self.logger.entry('info', f'{cve} maps to filter(s): {joined_filter_nums}')

        self.set_filter_entries(filter_nums, enable_filters_bool)
        self.get_filter_statuses(filter_nums)

        try:
            self.distribute_profile(segment_group_name)

        except ValueError as e:
            msg = str(e)
            self.logger.entry('critical', msg)
            sys.exit(msg)

        filter_setting = 'added' if enable_filters_bool else 'disabled'
        msg = f'Successfully {filter_setting} {cve} filter(s) to {self.profile_name} profile and distributed changes to ' \
              f'{segment_group_name} segment group'
        self.logger.entry('info', msg)

        status = self.json_response(200, msg)
        self.logger.entry('info', f'Finished')

        return status


def lambda_handler(event, context):
    profile_name = event['profile_name']
    segment_group_name = event['segment_group_name']
    cve = event['cve'].upper()
    enable_filters = event.get('enable_filters', 'true').lower()

    op = Op(APP_NAME, profile_name, print_logger=True)
    status = op.run(cve, segment_group_name, enable_filters)

    return status

