"""
Pure rules of a search, with no GitLab, file or terminal access: the records of
the project index as objects (models), which projects and branches to scan
(planning), time windows (timewindow), and the file and project filters.
"""

from glh.domain.file_filter import FileFilter
from glh.domain.models import as_project, IndexMeta, Project, ProjectIndex
from glh.domain.planning import build_scan_plan, ScanOptions, ScanPlan
from glh.domain.project_filter import ProjectFilter
from glh.domain.timewindow import parse_timestamp, TimeWindow

__all__ = ["FileFilter", "IndexMeta", "Project", "ProjectFilter", "ProjectIndex", "ScanOptions", "ScanPlan",
           "TimeWindow", "as_project", "build_scan_plan", "parse_timestamp"]
