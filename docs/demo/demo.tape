# VHS tape for docs/assets/demo.gif (see docs/demo/README.md).
# Runs the real CLI against the bundled Fake GitLab (artificial data only).

Output assets/demo.gif

Set Shell "bash"
Set FontSize 16
Set Width 1300
Set Height 400
Set Padding 18
Set Framerate 24
Set TypingSpeed 28ms
Set Theme "Catppuccin Mocha"

# Setup (not recorded): Fake GitLab on http://gitlab.example.com, a term list, a token.
Hide
Type "echo '127.0.0.1 gitlab.example.com' >> /etc/hosts; cd /tmp; printf 'password\napi_key\ntoken\n' > words.txt; export GITLAB_TOKEN=dev-token PS1='$ '"
Enter
Type "(python -m fakegitlab --host 127.0.0.1 --port 80 --scenario /vhs/demo/demo.yaml >/dev/null 2>&1 &); sleep 1.5; clear"
Enter
Sleep 2.5s
Show

Type "gitlab-harvester -u http://gitlab.example.com -t $GITLAB_TOKEN -f words.txt -b all --forks branch-diff --session audit"
Sleep 400ms
Enter
Sleep 10.5s
