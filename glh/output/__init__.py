"""
Where the results of a search go: the output layout (paths), the session sink,
downloaded files, the ZIP archive, and reading a session back (--resume).
"""

from glh.output.downloads import FileDownloader
from glh.output.layout import OutputLayout
from glh.output.sink import SearchOutput, SessionOutput

__all__ = ["FileDownloader", "OutputLayout", "SearchOutput", "SessionOutput"]
