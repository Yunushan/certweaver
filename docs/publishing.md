# Publishing to GitHub and GitLab

Replace placeholder maintainers and CODEOWNERS first.

```bash
git init
git add .
git commit -S -m "Initial CertWeaver release"
git branch -M main

git remote add github git@github.com:YOUR-ORG/certweaver.git
git remote add gitlab git@gitlab.com:YOUR-ORG/certweaver.git
git push -u github main
git push -u gitlab main
```

Enable protected branches, mandatory reviews, secret scanning, dependency updates, private vulnerability reporting, signed tags, and CI variables appropriate to each platform. Never put deployment secrets into repository variables that are exposed to untrusted pull/merge request pipelines.
