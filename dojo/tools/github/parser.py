__author__ = 'crackphantom'

import json
from dojo.models import Finding


def mapSeverity(githubSeverity):
    # This assumes github doesnt change possible values including case of graphql enum SecurityAdvisorySeverity 
    # https://developer.github.com/v4/enum/securityadvisoryseverity/
    
    # dojo.models.Finding.SEVERITIES
    
    # Note: Unknown would map to Info
    return {"CRITICAL": "Critical",
            "HIGH": "High",
            "MODERATE": "Medium",
            "LOW": "Low"}.get(githubSeverity, 'Info')



class GitHubVulnerableDependenciesParser(object):
    def __init__(self, json_filename, test):
        self.items = []
        data = {}
        try:
            data = json.load(json_filename)
        except(KeyError, ValueError):
            raise Exception('GitHub Vulnerable Dependencies response was invalid JSON')
        
        repo = data.get('data', {}).get('repository', {})
        repoName = repo.get('name', 'Unknown Github Repo')
        for alert in repo.get('vulnerabilityAlerts', {}).get('nodes', []):
            sv = alert.get('securityVulnerability', {})
            find = Finding(
                    title='{} - {} dependency "{}" {} has {}'.format(repoName,
                                           sv.get('package', {}).get('ecosystem', '?'),
                                           sv.get('package', {}).get('name', 'Unknown package'),
                                           sv.get('vulnerableVersionRange', 'Unknown version(s)'),
                                           sv.get('advisory', {}).get('summary'),
                                           ),
                    description=sv.get('advisory', {}).get('description', 'No description'),
                    severity=mapSeverity(sv.get('severity', 'Unknown')),
                    )
            self.items.append(find)
