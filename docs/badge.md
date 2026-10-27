# A badge for your site

If you have checked your site with Porch and want to say so, these are for
that. They say when you checked, not how it went.

| Badge | File | Size |
|---|---|---|
| ![Checked with Porch, light](assets/porch-badge-light.svg) | [`porch-badge-light.svg`](assets/porch-badge-light.svg) | 264 × 60 |
| ![Checked with Porch, dark](assets/porch-badge-dark.svg) | [`porch-badge-dark.svg`](assets/porch-badge-dark.svg) | 264 × 60 |
| ![Checked with Porch, small](assets/porch-badge-small.svg) | [`porch-badge-small.svg`](assets/porch-badge-small.svg) | 188 × 24 |

## Use

Download the files and put the date of your check where they say
`YYYY-MM-DD`, in each file:

```sh
perl -pi -e 's/YYYY-MM-DD/2026-10-27/g' porch-badge-*.svg
```

```powershell
Get-ChildItem porch-badge-*.svg | ForEach-Object { (Get-Content $_.FullName -Raw) -replace 'YYYY-MM-DD', '2026-10-27' | Set-Content $_.FullName -NoNewline -Encoding ascii }
```

Put them on your own server, beside your pages, and link them:

```html
<a href="https://porch.denyfirst.dev/">
  <picture>
    <source srcset="/porch-badge-dark.svg" media="(prefers-color-scheme: dark)">
    <img src="/porch-badge-light.svg" width="264" height="60" alt="Checked with Porch, 2026-10-27">
  </picture>
</a>
```

The small one is `<img src="/porch-badge-small.svg" width="188" height="24" alt="Checked with Porch, 2026-10-27">`.

When you check again, change the date. If you stop checking, take the badge
down.

## Why it is built this way

- **You serve it.** There is no badge on our server to link to, on purpose. A
  badge loaded from us would tell us the address of everyone who reads your
  page, and which page. Yours comes from your server and asks nobody else for
  anything.
- **A date, not a grade.** A grade is true on the day of the check and drifts
  after it, while the badge goes on saying it. A date says only what is so.
  The badge also names no check, so it is true whichever ones you ran.
- **Nothing in it runs.** Shapes, text and a title: no script, no link, no font
  or file from anywhere else. A test keeps it so, and keeps the files ASCII,
  so any editor or command can change the date without breaking them.
- **Not the report.** A published report tells a stranger which ports answer
  and which software versions you run. The badge says you looked. Keep what you
  found to yourself.
