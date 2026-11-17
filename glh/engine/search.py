# glh/engine/search.py
"""
SearchEngine: searches terms over the projects of an index.

The scan plan (which projects and branches pass the filters) is built once
(:func:`glh.domain.planning.build_scan_plan`) and shown as the 'Search plan'
block. The work is split into (term, project, branch) tasks
(:class:`~glh.engine.tasks.BranchTask`) taken from one queue by whichever worker
thread is free; this (main) thread merges the branch results of a project into
one record, hands records and checkpoints to the output sink and keeps the
progress. A term with failed retryable searches is not marked done.
"""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, IO, Iterable, Mapping
from urllib.parse import quote

import gitlab.exceptions
import requests.exceptions
from gitlab.const import SearchScope
from gitlab.v4.objects import Project as GitlabProject

from glh.domain.file_filter import FileFilter
from glh.domain.models import Project
from glh.domain.planning import branches_to_scan, build_scan_plan, ScanOptions, ScanPlan
from glh.domain.timewindow import TimeWindow
from glh.engine import workers as pool
from glh.engine.file_checks import FileChangeChecker, FileFetcher
from glh.engine.file_listing import FileLister
from glh.engine.tasks import BranchOutcome, BranchTask
from glh.gitlab import throttling, user_agents
from glh.gitlab.connection import GitLabConnection
from glh.gitlab.errors import describe_api_error
from glh.output.downloads import FileDownloader
from glh.output.records import BranchResult, Checkpoint, Hit, INACCESSIBLE, NOT_FOUND, ProjectResult
from glh.output.sink import SearchOutput
from glh.ui import statusline
from glh.ui.blocks import Row
from glh.ui.formatting import format_clock, format_duration, human_int, plural
from glh.ui.progress import Progress

# datetime.UTC exists only on Python 3.11+, while the package supports 3.10.
UTC = timezone.utc


def describe_unsearched(counts: Counter[str]) -> str:
    """'; 3 searches NOT POSSIBLE: 2 no access (HTTP 403), 1 not found (HTTP 404)', or '' without any."""
    total = counts[INACCESSIBLE] + counts[NOT_FOUND]
    if not total:
        return ""
    kinds = [f"{counts[INACCESSIBLE]:,} no access (HTTP 403)" if counts[INACCESSIBLE] else "",
             f"{counts[NOT_FOUND]:,} not found (HTTP 404)" if counts[NOT_FOUND] else ""]
    return f"; {plural(total, 'search', 'searches')} NOT POSSIBLE: {', '.join(k for k in kinds if k)}"


class SearchEngine:
    """Term search (and the files-only mode) over a scan plan, see the module doc."""

    def __init__(self, connection: GitLabConnection, active: pool.ActiveTasks, changes: FileChangeChecker,
                 fetcher: FileFetcher, lister: FileLister, logger: logging.Logger) -> None:
        self.connection = connection
        # What every thread is searching right now (status line, slow-task reports).
        self.active = active
        self.changes = changes
        self.fetcher = fetcher
        self.lister = lister
        self.logger = logger
        # Terms of the last search that had failed (retryable) searches.
        self.incomplete_terms: list[str] = []
        # Searches of the last run that could not run at all, per kind (INACCESSIBLE, NOT_FOUND).
        self.unsearched: Counter[str] = Counter()
        # Report a search task still running after this many seconds (and again
        # every as many seconds); 0 disables. Parallel search only.
        self.slow_task_report: float = 300.0

    # -------------------------------------------------------------------- plan

    def plan_rows(self, keywords: list[str], plan: ScanPlan, options: ScanOptions,
                  downloader: FileDownloader | None) -> list[Row]:
        """The rows of the 'Search plan' block."""
        if options.files_only:
            first: list[Row] = [
                ("files", f"every file matching {options.file_filter.describe()} (no term)"),
                ("listing", options.file_listing),
            ]
        else:
            first = [("terms", f"{len(keywords):,}")]
            if options.file_filter:
                first.append(("files", options.file_filter.describe()))
        pacing = self.connection.factory.pacing
        return [
            *first,
            ("projects", f"{plan.project_count:,} of {plan.total_projects:,}"),
            ("skipped", plan.skipped_reasons()),
            ("branches", f"{plan.branch_count:,}"),
            ("forks", f"{plan.forks_by_name:,} compared by branch name only: the index has no branch commits "
                      "(rebuild it with --dump-projects)" if plan.forks_by_name else ""),
            ("files changed", options.file_window.describe() if options.file_window else ""),
            ("downloads", downloader.target() if downloader is not None else ""),
            ("parallel", self.connection.concurrency_text()),
            ("rate limit", throttling.describe(pacing.index_rpm, pacing.search_rpm)),
            ("jitter", throttling.format_jitter(pacing.jitter)),
            ("user agent", user_agents.describe(self.connection.factory.settings.user_agents)),
        ]

    # ------------------------------------------------------------------ search

    def search_keywords(
            self,
            projects: Iterable[Project | Mapping[str, Any]],
            keywords: list[str],
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
            output: SearchOutput | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search ``keywords`` over ``projects`` (the whole index) with the scan plan of ``options``.

        Progress counts only planned projects, so projects excluded by --forks
        skip, --started-from or empty repositories never inflate the totals.

        Args:
            projects: The whole project index (Projects, or index records as dicts).
            keywords: Search terms.
            options: Scan options (branches, forks, activity, file filters).
            hit_counter: Initial hit counter.
            session_file: Open session JSONL to stream hits and checkpoints to
                (shortcut for ``output=SearchOutput(session_file)``).
            output: Where hits, checkpoints and files go (glh/output/sink.py); its
                ``downloader`` saves every file with hits (--download-files),
                and each downloaded hit gets a "file" key with the local path.

        Returns:
            ([{"term", "result"}, ...], total hit counter).
        """
        output = output or SearchOutput(session_file)
        downloader = output.downloader
        plan = build_scan_plan(projects, options)
        n_terms = len(keywords)
        terms_text = plural(n_terms, "term")
        hits_before = hit_counter
        if options.files_only:
            self.lister.reset()
        statusline.STATUS.write_block("Search plan", self.plan_rows(keywords, plan, options, downloader))

        with Progress("Searching", total=plan.project_count, unit="projects", rounds=n_terms) as progress:
            res, hit_counter = self._run_search(
                keywords, plan, hit_counter=hit_counter, output=output,
                progress=progress, checkpoints=True, file_window=options.file_window or None,
                file_filter=options.file_filter or None,
                file_listing=options.file_listing if options.files_only else None,
            )
            checks = (f", {plural(self.changes.checks, 'file check')}" if options.file_window else "")
            incomplete = (f"; INCOMPLETE: {plural(len(self.incomplete_terms), 'term')} "
                          f"with failed searches, not marked done" if self.incomplete_terms else "")
            incomplete += describe_unsearched(self.unsearched)
            if options.files_only and self.lister.counts:
                listed = ", ".join(f"{plural(n, 'branch', 'branches')} by {how}"
                                   for how, n in sorted(self.lister.counts.items()))
                checks += f"; files listed: {listed}"
            progress.finish(
                f"Search finished: {terms_text} x {plural(plan.project_count, 'project')}, "
                f"{plural(hit_counter - hits_before, 'hit')}{checks} in "
                f"{format_duration(progress.elapsed)}{incomplete}"
            )

        return res, hit_counter

    def search_keyword(
            self,
            projects: Iterable[Project | Mapping[str, Any]],
            term: str,
            *,
            options: ScanOptions,
            hit_counter: int = 0,
            session_file: IO | None = None,
            plan: ScanPlan | None = None,
            progress: Progress | None = None,
            output: SearchOutput | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search a single term across the planned projects (no checkpoint record).

        Returns:
            (per-project results, updated hit counter).
        """
        plan = plan or build_scan_plan(projects, options)
        own = progress is None
        progress = progress or Progress(f"Searching '{term}'", total=plan.project_count).start()
        try:
            res, hit_counter = self._run_search([term], plan, hit_counter=hit_counter,
                                                output=output or SearchOutput(session_file),
                                                progress=progress, checkpoints=False,
                                                file_window=options.file_window or None,
                                                file_filter=options.file_filter or None)
        finally:
            if own:
                progress.finish()
        return res[0]["result"], hit_counter

    # ------------------------------------------------------------- one task

    def search_branch(self, task: BranchTask) -> BranchOutcome:
        """
        Worker: search one term in one branch of one project (all result pages).

        Returns:
            The hits, and the trouble met (BranchOutcome): a retryable error
            (5xx, 429 after retries, 401, timeout, network, invalid response)
            that may have hidden hits keeps the term open; 403/404 (no access,
            not found) are logged and counted as gaps in the coverage.
        """
        name = task.project_name
        n_branches = len(task.branches)
        label = f"{name} @ {task.branch}" + (f" [{task.branch_no + 1}/{n_branches}]" if n_branches > 1 else "")
        doing = (f"listing the files ({task.term}) of" if task.file_listing is not None
                 else f"searching '{task.term}' in")
        with self.active.running(label, report=f"{doing} {name} @ {task.branch}"):
            if self.connection.concurrency <= 1:
                # Inline (main thread): show the new task now. Worker threads
                # leave redraws to the status ticker.
                statusline.STATUS.refresh()
            if task.file_listing is not None:
                return self.lister.collect(task)
            return self._search_term(task)

    def _search_term(self, task: BranchTask) -> BranchOutcome:
        """search_branch() for a term, while the task is registered as running."""
        name = task.project_name
        project_obj: GitlabProject = self.connection.require().projects.get(task.project.id, lazy=True)
        path_filter = self._path_filter(task) if task.file_window or task.file_filter else None
        on_files = self._file_saver(task) if task.downloader is not None else None
        query = task.file_filter.query(task.term) if task.file_filter else None
        errors: list[BaseException] = []
        try:
            hits, _ = self.scan_branch(project=project_obj, branch=task.branch, term=task.term,
                                       project_url=task.project.web_url, path_filter=path_filter,
                                       errors=errors, query=query, on_files=on_files)
        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                name, task.branch, describe_api_error(e))
            self.logger.debug("Full error searching %s @ %s: %s", name, task.branch, e)
            errors.append(e)
            hits = []
        return BranchOutcome.of(task, hits, errors)

    def _path_filter(self, task: BranchTask) -> Callable[[str], bool]:
        """Keep a result path? The file filters first (free), then --file-changed-* (one request)."""
        def keep(path: str) -> bool:
            if task.file_filter and not task.file_filter.matches(path):
                return False
            return not task.file_window or self.changes.changed(task.project.id, task.branch, path,
                                                                task.file_window)
        return keep

    def _file_saver(self, task: BranchTask) -> Callable[[list[str]], dict[str, str]]:
        """Download the files with hits of the task (--download-files)."""
        def save(paths: list[str]) -> dict[str, str]:
            return self.fetcher.download(task, paths)
        return save

    # ------------------------------------------------------------ all tasks

    def _run_search(
            self,
            terms: list[str],
            plan: ScanPlan,
            *,
            hit_counter: int,
            output: SearchOutput,
            progress: Progress,
            checkpoints: bool,
            file_window: TimeWindow | None = None,
            file_filter: FileFilter | None = None,
            file_listing: str | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        """
        Search ``terms`` over ``plan`` with the connection's worker threads.

        Work is split into (term, project, branch) tasks taken from one shared
        queue by whichever worker is free, so a few huge repositories don't
        leave other workers idle. Workers only do HTTP (search, and the files
        with hits for ``output.downloader``); this (main) thread merges branch
        results into one record per (term, project), hands records to
        ``output`` and updates progress:

        - a project record is written when all its branches are done
          (with workers > 1, records appear in completion order);
        - ``keyword_done`` is written when every task of the term and of all
          earlier terms is done, so checkpoints keep the term order and
          ``--resume`` stays correct; terms still overlap (no idle barrier).

        With workers == 1 the tasks run inline, in order, exactly as a
        sequential scan.
        """
        n_terms = len(terms)
        hits_before = hit_counter
        term_hits = [0] * n_terms
        projects_left = [plan.project_count] * n_terms
        results: list[list[tuple[int, ProjectResult]]] = [[] for _ in terms]
        partial: dict[tuple[int, int], dict[int, list[Hit]]] = {}
        state = {"next_term": 0, "term_started": progress.elapsed}
        # Failed (retryable) searches per term: such a term is not marked done.
        term_failures: list[list[str]] = [[] for _ in terms]
        # Searches that could not run (403/404) per term: (kind, reason); the term is done, with gaps.
        term_unsearched: list[list[tuple[str, str]]] = [[] for _ in terms]
        self.incomplete_terms = []
        self.unsearched = Counter()
        # When the first task of each term was handed out (feeder thread with workers > 1).
        term_begun: dict[int, float] = {}

        def label(number: int) -> str:
            term = terms[number]
            return f"Searching '{term}'" + (f" ({number + 1}/{n_terms})" if n_terms > 1 else "")

        def close_finished_terms() -> None:
            while state["next_term"] < n_terms and projects_left[state["next_term"]] == 0:
                number = state["next_term"]
                failures = term_failures[number]
                if failures:
                    self.incomplete_terms.append(terms[number])
                if checkpoints:
                    # keyword_done (the --resume checkpoint) only for terms searched completely;
                    # flushed, durable even if the process is killed.
                    output.checkpoint(Checkpoint.for_term(
                        terms[number], hits_before + sum(term_hits[:number + 1]), datetime.now(UTC).isoformat(),
                        failures, term_unsearched[number]))
                failed = (f"; {plural(len(failures), 'search', 'searches')} FAILED, "
                          f"not marked done" if failures else "")
                failed += describe_unsearched(Counter(kind for kind, _ in term_unsearched[number]))
                if checkpoints and (n_terms > 1 or failures or term_unsearched[number]):
                    progress.note(
                        f"Term {number + 1}/{n_terms} '{terms[number]}': "
                        f"{plural(plan.project_count, 'project')}, "
                        f"{plural(term_hits[number], 'hit')} in "
                        f"{format_duration(progress.elapsed - state['term_started'])}{failed}"
                    )
                state["term_started"] = progress.elapsed
                state["next_term"] += 1
                if state["next_term"] < n_terms:
                    progress.start_round(state["next_term"] + 1, label(state["next_term"]),
                                         started=term_begun.get(state["next_term"]))
                    progress.done = plan.project_count - projects_left[state["next_term"]]

        def tasks():
            for term_no, term in enumerate(terms):
                term_begun.setdefault(term_no, progress.clock())
                for project_no, (project, branches) in enumerate(plan.targets):
                    for branch_no, _branch in enumerate(branches):
                        yield BranchTask(term_no, term, project_no, project, branches, branch_no, file_window,
                                         file_filter, output.downloader, file_listing)

        def report_slow_tasks() -> None:
            # Main thread only. A search can legitimately run for hours (huge
            # repositories, rate limits): say so instead of looking hung.
            if not self.slow_task_report:
                return
            now = self.active.clock()
            for running in self.active.snapshot():
                since = running.reported_at if running.reported_at is not None else running.started
                if now - since >= self.slow_task_report:
                    running.reported_at = now
                    details = ", ".join(x for x in (running.step, running.waiting) if x)
                    progress.note(
                        f"Still {running.report}"
                        f"{f' ({details})' if details else ''}: running for "
                        f"{format_duration(self.active.elapsed(running))}"
                    )

        if n_terms:
            progress.start_round(1, label(0))
        progress.set_info(f"{human_int(hit_counter)} hits")
        close_finished_terms()  # terms without planned projects

        # The status line shows the tasks running right now (the longest-running
        # first), not the last finished one: the last task of a scan may run long
        # after all the others are done.
        previous_provider, previous_lines = progress.detail_provider, progress.detail_lines_provider
        progress.detail_provider = lambda: self.active.describe(format_clock)
        progress.detail_lines_provider = lambda: self.active.lines(format_clock)
        progress.info_label = "found"

        try:
            tasks_iter = pool.imap_unordered(self.search_branch, tasks(), workers=self.connection.concurrency,
                                             initializer=self.connection.init_worker_client,
                                             on_idle=report_slow_tasks)
            for done in tasks_iter:
                task: BranchTask = done.item
                outcome: BranchOutcome = done.unwrap()
                hits = outcome.hits
                if outcome.failure:
                    term_failures[task.term_no].append(outcome.failure)
                if outcome.unsearched:
                    term_unsearched[task.term_no].append((outcome.unsearched, outcome.reason))
                    self.unsearched[outcome.unsearched] += 1
                key = (task.term_no, task.project_no)
                got = partial.setdefault(key, {})
                got[task.branch_no] = hits
                if len(got) < len(task.branches):
                    continue

                # All branches of this (term, project) are done: one session record.
                del partial[key]
                project = task.project
                by_branch = [BranchResult(b, tuple(got[i])) for i, b in enumerate(task.branches) if got[i]]
                found = sum(len(h) for h in got.values())
                hit_counter += found
                term_hits[task.term_no] += found
                if by_branch:
                    out = ProjectResult.for_project(project, by_branch)
                    results[task.term_no].append((task.project_no, out))
                    output.hit(task.term, out)

                projects_left[task.term_no] -= 1
                if task.term_no == state["next_term"]:
                    progress.done = plan.project_count - projects_left[task.term_no]
                progress.completed_units = sum(plan.project_count - left for left in projects_left)
                progress.found(found)
                progress.set_info(f"{human_int(hit_counter)} hits")
                progress.advance(0)
                close_finished_terms()
                report_slow_tasks()

        finally:
            # An interrupted search keeps the running tasks in its "stopped" line.
            progress.detail = self.active.describe(format_clock) or progress.detail
            progress.detail_provider, progress.detail_lines_provider = previous_provider, previous_lines

        res = [{"term": term, "result": [out.to_record() for _, out in sorted(results[i], key=lambda x: x[0])]}
               for i, term in enumerate(terms)]
        return res, hit_counter

    # ---------------------------------------------------------- single scans

    def scan_project(
            self,
            project: Project,
            term: str,
            *,
            options: ScanOptions,
            projects_by_id: Mapping[int, Project] | None = None,
            branches: list[str] | tuple[str, ...] | None = None,
            progress: Progress | None = None,
            hit_counter: int = 0,
    ) -> tuple[list[BranchResult], int]:
        """
        Scan one project for a term across its selected branches (branches_to_scan() if None).

        Returns:
            (the branches with hits, updated hit counter).
        """
        res: list[BranchResult] = []

        project_obj: GitlabProject = self.connection.require().projects.get(project.id, lazy=True)
        project_url: str = project.web_url

        if branches is None:
            branches = branches_to_scan(project, options, projects_by_id=projects_by_id)
        if not branches:
            return [], hit_counter

        br_len: int = len(branches)
        name = project.name

        for num, b in enumerate(branches):
            if progress is not None:
                branch_info = b if br_len == 1 else f"{b} [{num + 1}/{br_len}]"
                progress.set_detail(f"{name} @ {branch_info}")

            try:
                s_res, hit_counter = self.scan_branch(
                    project=project_obj,
                    branch=b,
                    term=term,
                    project_url=project_url,
                    hit_counter=hit_counter,
                )
                if s_res:
                    res.append(BranchResult(b, tuple(s_res)))
            except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
                self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                    project_url, b, describe_api_error(e))
                self.logger.debug("Full error searching %s @ %s: %s", project_url, b, e)

        return res, hit_counter

    def scan_branch(
            self,
            project: GitlabProject,
            branch: str,
            term: str,
            project_url: str,
            hit_counter: int = 0,
            per_page: int = 100,
            path_filter: Callable[[str], bool] | None = None,
            errors: list[BaseException] | None = None,
            query: str | None = None,
            on_files: Callable[[list[str]], dict[str, str]] | None = None,
            **kwargs: Any,
    ) -> tuple[list[Hit], int]:
        """
        Search for a term inside a specific branch using GitLab blob search.

        Args:
            project: GitLab Project object (lazy instance allowed).
            branch: Branch name to scan.
            term: Search term.
            project_url: Base web URL of the project.
            per_page: Number of results per page.
            hit_counter: Global hit counter to be incremented.
            path_filter: Optional predicate on the file path; hits in files for
                which it returns False are dropped (file name and time filters).
            errors: Optional list that receives the API error that stopped the
                search early (results of earlier pages are still returned).
            query: Search string sent to GitLab instead of ``term`` (the term
                plus --filename/--extension filters); ``term`` is still logged.
            on_files: Called once with the distinct paths of the kept results
                (--download-files); returns {path: local file} and every hit
                of such a path gets a "file" key.
            **kwargs: Additional parameters passed to GitLab search API.

        Returns:
            (the hits: link, snippet and downloaded file; updated hit counter).
        """
        self.connection.require()
        res: list[Hit] = []
        page: int = 1

        search_results: list[dict[str, Any]] = []
        try:
            while True:
                if page > 1:
                    self.active.set_step(f"page {page}")
                batch = project.search(scope=SearchScope.BLOBS, ref=branch, search=query or term,
                                       page=page, per_page=per_page, **kwargs)

                search_results.extend(batch)
                page += 1

                if len(batch) < per_page:
                    break

        except (gitlab.exceptions.GitlabError, requests.exceptions.RequestException) as e:
            # Keep results of already fetched pages; a timeout must not abort the whole scan.
            self.logger.warning("Could not search %s @ %s (%s); skipping it, continuing",
                                project_url, branch, describe_api_error(e))
            self.logger.debug("Full error searching %s @ %s: %s", project_url, branch, e)
            if errors is not None:
                errors.append(e)

        if path_filter is not None and search_results:
            verdict: dict[str, bool] = {}
            search_results = [x for x in search_results
                              if verdict.setdefault(x["path"], path_filter(x["path"]) if x["path"] not in verdict
                                                    else verdict[x["path"]])]

        # Branch names and paths may contain '#', '?', '%', spaces, etc.
        branch_url: str = f"{project_url}/-/blob/{quote(branch, safe='/')}"
        if search_results:
            local: dict[str, str] = {}
            if on_files is not None:
                local = on_files(list(dict.fromkeys(x["path"] for x in search_results)))
            res = [Hit(url=f"{branch_url}/{quote(x['path'], safe='/')}#L{x['startline']}", data=x.get("data", ""),
                       file=local.get(x["path"])) for x in search_results]

            for hit in res:
                self.logger.info(f"[+] Hitted '{term}': {hit.url}")
            hit_counter += len(res)

        return res, hit_counter
