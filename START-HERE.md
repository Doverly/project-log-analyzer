<!-- © AngelaMos | 2026 -->
<!-- START-HERE.md -->

# Project 1 — Security Log Analyzer

Hey Derek, this is your first project. Read this entire page before doing anything else.

---

## Watch These First (Optional but Recommended)

If Python is new to you, spend an hour with one of these before touching the code. You don't need to finish them — even 30-40 minutes will make the study guide click a lot faster.

- **1 hour intro (recommended):** https://youtu.be/8KCuHHeC_M0
- **2 hour full course (if you want more depth):** https://youtu.be/K5KVEU3aaeQ

You don't need to memorize anything. Just get a feel for what Python looks like — variables, functions, loops, dictionaries. Everything else will make sense when you read the actual code.

---

## What This Is

This is a Python tool that analyzes security logs — authentication logs and firewall logs — to detect common attack patterns like brute force attempts, port scans, privilege escalation, and suspicious off-hours activity. It's the kind of detection logic that runs inside enterprise SIEMs like Splunk or Elastic.

I built this for you. Your job is to **study it, understand how it works, and be able to explain it in an interview like you built it.** By the time you're done, you should be able to walk someone through every function in the code and explain why each detection matters in a SOC environment.

---

## What's In This Repo

| File | What It Is | Goes on YOUR GitHub? |
|------|-----------|---------------------|
| `START-HERE.md` | This file. Instructions for you. | **No** — delete this before pushing to your GitHub |
| `study-guide.md` | Line-by-line walkthrough, interview prep, exercises | **No** — this is private study material, not for your public profile |
| `analyzer.py` | The main tool | **Yes** |
| `samples/auth.log` | Sample authentication log with attack patterns | **Yes** |
| `samples/firewall.log` | Sample firewall log with port scan activity | **Yes** |
| `README.md` | Project README that explains the tool | **Yes** |

The files marked "Yes" are your public project. The files marked "No" are just for you to learn from — they stay off your GitHub.

---

## Step-by-Step: What to Do

### Step 0: Set up SSH for GitHub (one-time setup)

GitHub requires SSH keys to push and pull repos. You only have to do this once and then it works for everything going forward.

**Check if you already have an SSH key:**

```bash
ls ~/.ssh/id_ed25519.pub
```

If that prints a file path, you already have a key — skip to "Add your key to GitHub" below. If it says "No such file", generate one:

**Generate a new SSH key:**

```bash
ssh-keygen -t ed25519 -C "your-email@example.com"
```

It'll ask where to save it — just hit Enter to accept the default. It'll ask for a passphrase — you can hit Enter for no passphrase (fine for now), or set one if you want.

**Start the SSH agent and add your key:**

```bash
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
```

**Copy your public key:**

On Linux/WSL:
```bash
cat ~/.ssh/id_ed25519.pub
```

On Mac:
```bash
pbcopy < ~/.ssh/id_ed25519.pub
```

Either way, copy the entire output. It starts with `ssh-ed25519` and ends with your email.

**Add your key to GitHub:**

1. Go to [github.com/settings/keys](https://github.com/settings/keys)
2. Click "New SSH key"
3. Title: whatever you want (e.g., "My laptop")
4. Key type: Authentication Key
5. Paste your public key into the "Key" box
6. Click "Add SSH key"

**Test the connection:**

```bash
ssh -T git@github.com
```

It might ask if you want to continue connecting — type `yes`. If it says "Hi YOUR-USERNAME! You've authenticated" then you're good. If it says "Permission denied" something went wrong — text me and we'll figure it out.

### Step 1: Clone this repo to your local machine

```bash
git clone git@github.com:CarterPerez-Dev/project-log-analyzer.git
cd log-analyzer
```

### Step 2: Make sure it runs

Run the tool against both sample logs:

```bash
python3 analyzer.py samples/auth.log
```

You should see a formatted report with HIGH, MEDIUM, and LOW severity findings. Then run the second log:

```bash
python3 analyzer.py samples/firewall.log
```

If both commands produce reports, you're good.

### Step 3: Study the project

Open `study-guide.md` and work through it section by section:

1. **Read the README** — understand what the tool does at a high level
2. **Run the tool again** and really look at the output. What does each finding mean?
3. **Open `analyzer.py`** and read through it with the study guide next to you. The guide explains every function and why it matters.
4. **Do the exercises** at the bottom of the study guide
5. **Practice explaining the project out loud.** Seriously. Say it out loud like you're in an interview. It feels weird but it's the single best thing you can do to prepare.

### Step 4: Fill in "What I Learned"

At the bottom of `README.md` there's a section called "What I Learned" with an empty comment block. Write 3-5 sentences about what you took away from this project. This is what makes the project yours — interviewers can see you actually engaged with it, not just forked something.

### Step 5: Create YOUR repo on GitHub

Go to [github.com/new](https://github.com/new) and create a new repository:

- **Name:** `security-log-analyzer`
- **Description:** `Python tool that analyzes authentication and firewall logs to detect brute force attacks, port scans, privilege escalation, and suspicious activity with MITRE ATT&CK mapping`
- **Visibility:** Public
- **Do NOT** check "Add a README" or "Add .gitignore"

### Step 6: Copy the project files to a new folder

```bash
cd ~
mkdir security-log-analyzer
cd security-log-analyzer
```

Copy only the project files (not the study materials):

```bash
cp ~/log-analyzer/analyzer.py .
cp ~/log-analyzer/README.md .
mkdir samples
cp ~/log-analyzer/samples/*.log samples/
```

### Step 7: Initialize git and push to YOUR GitHub

```bash
git init
git add analyzer.py README.md samples/auth.log samples/firewall.log
git commit -m "security log analyzer"
git branch -M main
git remote add origin git@github.com:Doverly/security-log-analyzer.git
git push -u origin main
```

### Step 8: Verify it looks right

Go to `https://github.com/Doverly/security-log-analyzer` in your browser. You should see:

- Your README with the detection table, sample output, and configuration reference
- `analyzer.py` in the file list
- A `samples/` folder with both log files
- NO `study-guide.md` or `START-HERE.md` — those stay private

---
