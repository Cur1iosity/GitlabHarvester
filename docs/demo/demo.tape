# VHS tape for the README demo GIF (see docs/demo/README.md).
# Writes docs/demo/out/demo.gif (git-ignored); CI publishes it to the demo-assets branch.
# Installs the CLI with pipx (from wheels of this checkout, see Dockerfile) and
# runs it against the bundled Fake GitLab (artificial data only).

Output demo/out/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1300
Set Height 560
Set Padding 18
Set Framerate 24
Set TypingSpeed 28ms
Set Theme "Catppuccin Mocha"

# Setup (not recorded): Fake GitLab on https://gitlab.example.com with a certificate
# from a throwaway private CA that the shell trusts; see setup.sh.
Hide
Type "source /vhs/demo/setup.sh"
Enter
Sleep 4s
Show

Type "pipx install gitlab-harvester"
Sleep 300ms
Enter
Wait+Screen@90s /done!/
Sleep 1s

Type "gitlab-harvester -u https://gitlab.example.com -t $GITLAB_TOKEN -f words.txt -b all --forks branch-diff --session audit"
Sleep 400ms
Enter
Wait+Screen@90s /Done\. Keywords/
Sleep 3s
