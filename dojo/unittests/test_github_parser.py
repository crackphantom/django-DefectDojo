__author__ = 'crackphantom'

from django.test import TestCase
from dojo.tools.github.parser import GitHubVulnerableDependenciesParser
from dojo.models import Test


class TestGitHubVulnerableDependenciesParser(TestCase):
        

    def testGitHubParserWithNoFinding(self):
        exceptionThrown = False
        testfile = open("dojo/unittests/scans/github/no_vuln.json")
        try:
            
            parser = GitHubVulnerableDependenciesParser(testfile, Test())
        except Exception as e:
            exceptionThrown = True
            self.assertEquals("GitHub Vulnerable Dependencies response was invalid JSON", str(e))
        self.assertTrue(exceptionThrown)

    def testGitHubParserWithOneFinding(self):
        testfile = open("dojo/unittests/scans/github/one_vuln.json")
        parser = GitHubVulnerableDependenciesParser(testfile, Test())
        self.assertEqual(1, len(parser.items))
        finding = parser.items[0]
        self.assertEqual(finding.title, 'fake-repo - NPM dependency "fakemodule" < 1.1.0 has High severity vulnerability that affects fakemodule')
        self.assertEqual(finding.description, 'A vulnerability was found in fakemodule before v1.1.0, the affected versions of this package are vulnerable to Bad Behavior attacks.')
        self.assertEqual(finding.severity, 'High')
        
