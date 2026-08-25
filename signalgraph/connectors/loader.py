"""
Auto-register all connectors.
"""

from signalgraph.connectors.registry import ConnectorRegistry
from signalgraph.connectors.okta import OktaConnector
from signalgraph.connectors.aws import AWSConnector
from signalgraph.connectors.github import GitHubConnector
from signalgraph.connectors.edr import EDRConnector
from signalgraph.connectors.jira import JiraConnector


def register_all_connectors():
    """Register all available connectors."""
    ConnectorRegistry.register("okta", OktaConnector)
    ConnectorRegistry.register("aws", AWSConnector)
    ConnectorRegistry.register("github", GitHubConnector)
    ConnectorRegistry.register("edr", EDRConnector)
    ConnectorRegistry.register("jira", JiraConnector)
