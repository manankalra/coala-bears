import json

from coalib.bearlib.abstractions.Linter import linter
from coalib.results.Result import Result
from dependency_management.requirements.PipRequirement import PipRequirement


@linter(executable='dodgy',
        use_stdout=True,
        use_stderr=False,
        global_bear=True)
class DodgyBear:
    """
    Checks Python files for "dodgy" looking values such
    as AWS secret keys, passwords, SCM diff check-ins,
    SSH keys and any other type of hardcoded secrets.
    """

    LANGUAGES = {'Python'}
    REQUIREMENTS = {PipRequirement('dodgy', '0.1.9')}
    AUTHORS = {'The coala developers'}
    AUTHORS_EMAILS = {'coala-devel@googlegroups.com'}
    LICENSE = 'AGPL-3.0'
    CAN_DETECT = {'Security', 'Hardcoded Secret',
                  'SCM Diff Check-in', 'SSH Keys'}
    SEE_MORE = 'https://github.com/landscapeio/dodgy'

    @staticmethod
    def create_arguments(config_file):
        return []

    def process_output(self, output, filename, file):
        for issue in json.loads(output)['warnings']:
            yield Result.from_values(origin=self,
                                     message=issue['message'],
                                     file=issue['path'],
                                     line=issue['line'])
