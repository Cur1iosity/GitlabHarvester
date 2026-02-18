class GitlabHarvesterError(Exception):
    """
    Base exception for GitlabHarvester-specific errors.

    Raised to indicate incorrect usage or unrecoverable conditions
    within the harvester workflow, such as attempting to access the
    GitLab API before client initialization.
    """
    pass
