# Plan: Autonomous Repository Creation & Development for Aton

## Goal

Enable Aton to autonomously:
1. Create new GitHub repositories in the `alphatoncapital` organization from Telegram ideas
2. Initialize project scaffolding (package.json, README, basic structure)
3. Begin working on ideas using the openclaw coding-agent skill
4. Track progress and report back to Telegram

## Current State Analysis

### What We Have

**Telegram Bot (`bot/index.js`):**
- `/propose [idea]` command - captures ideas and creates GitHub issues
- `createGitHubIssue()` function - creates issues in `atoncap/ideas`
- SQLite database tracking ideas with status field
- AI-powered idea structuring via Claude Haiku
- GitHub token with full permissions (loaded from `.secrets/github-token.txt`)

**OpenClaw Framework (`openclaw.json`):**
- Agent profile: `developer`
- Tools allowed: `file_read`, `file_write`, `file_edit`, `http_request`, `exec`
- Safe binaries: `curl`, `jq`, `node`, `npm`, `npx`, `yarn`, `git`, `tsc`, `blueprint`
- Sandbox mode with 600s timeout
- Autonomy enabled with supervised mode

**Skills Available:**
- `coding-agent` - Background process for code generation (Codex, Claude Code, Pi)
- `agent-builder` - Create new openclaw agent workspaces
- `github-pr` - PR management via `gh` CLI
- `github` - General GitHub operations via `gh` CLI

### What's Missing

1. **Repository Creation Function** - No code to create repos via GitHub API
2. **Project Scaffolding** - No templates for initializing new projects
3. **Work Queue System** - No mechanism to queue and track autonomous development work
4. **Coding Agent Integration** - Bot doesn't invoke coding-agent skill
5. **Progress Reporting** - No way to report dev progress back to Telegram

## Constraints & Dependencies

### GitHub API Requirements
- Endpoint: `POST /orgs/{org}/repos`
- Required scope: `repo` (already have with classic token)
- Rate limit: 5000 requests/hour (authenticated)
- Repo names must be lowercase, alphanumeric, hyphens allowed

### OpenClaw Sandbox Limitations
- Docker container with 2GB memory, 2 CPUs
- 600s (10 min) timeout per exec
- Network access via proxy (172.30.0.10)
- Safe binaries only - `gh` CLI not in allowlist!

### Risk Assessment
- **Medium Risk**: Autonomous repo creation could create spam repos
  - Mitigation: Rate limit to 1 repo per hour, require admin confirmation for production
- **Medium Risk**: Coding agent could produce low-quality code
  - Mitigation: Always create PRs, never direct push to main
- **Low Risk**: Token exposure in logs
  - Mitigation: Already configured redaction patterns in openclaw.json

## Architecture Design

### Data Flow

```
Telegram User
    │
    ▼ /propose or /build
┌─────────────────────────────────────┐
│  Telegram Bot (index.js)           │
│  - Receive idea                     │
│  - AI structures idea → project spec │
│  - Validate: is this buildable?     │
└─────────────────────────────────────┘
    │
    ▼ createProjectRepo()
┌─────────────────────────────────────┐
│  GitHub API                         │
│  - POST /orgs/atoncap/repos         │
│  - Initialize with README           │
│  - Create initial issue             │
└─────────────────────────────────────┘
    │
    ▼ queueWork()
┌─────────────────────────────────────┐
│  Work Queue (SQLite)               │
│  - Store: repo, task, status        │
│  - Worker picks up pending tasks    │
└─────────────────────────────────────┘
    │
    ▼ startCodingAgent()
┌─────────────────────────────────────┐
│  Coding Agent (background)         │
│  - Clone repo to /tmp              │
│  - Execute task via claude/codex   │
│  - Commit changes to feature branch │
│  - Create PR                        │
└─────────────────────────────────────┘
    │
    ▼ reportProgress()
┌─────────────────────────────────────┐
│  Telegram Notification             │
│  - "PR created: [link]"            │
│  - "Work completed for: [idea]"    │
└─────────────────────────────────────┘
```

### New Database Tables

```sql
CREATE TABLE IF NOT EXISTS projects (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  idea_id INTEGER,
  repo_name TEXT UNIQUE,
  repo_url TEXT,
  created_by_user_id INTEGER,
  created_from_chat_id INTEGER,
  status TEXT DEFAULT 'created', -- created, in_progress, completed, failed
  created_at TEXT,
  updated_at TEXT,
  FOREIGN KEY (idea_id) REFERENCES ideas(id)
);

CREATE TABLE IF NOT EXISTS work_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  project_id INTEGER,
  task_type TEXT, -- scaffold, feature, bugfix, docs
  task_description TEXT,
  priority INTEGER DEFAULT 5,
  status TEXT DEFAULT 'pending', -- pending, running, completed, failed
  agent_session_id TEXT,
  started_at TEXT,
  completed_at TEXT,
  result_pr_url TEXT,
  error_message TEXT,
  FOREIGN KEY (project_id) REFERENCES projects(id)
);
```

### New Bot Commands

| Command | Description |
|---------|-------------|
| `/build [idea]` | Create a new repo and start building |
| `/build_status` | Check status of active builds |
| `/project [name]` | Get info about a project |
| `/queue` | View the work queue |

### New Functions

```javascript
// 1. Create a new repository
async function createProjectRepo(projectName, description, userId, chatId) {
  // Validate name (alphanumeric, hyphens only)
  // Check rate limits
  // POST to GitHub API
  // Initialize with README template
  // Return repo URL
}

// 2. Add to work queue
function queueWork(projectId, taskType, description, priority = 5) {
  // Insert into work_queue
  // Return task ID
}

// 3. Process work queue (called periodically)
async function processWorkQueue() {
  // Get oldest pending task
  // Clone repo to temp directory
  // Invoke coding agent
  // Monitor progress
  // Create PR when done
  // Update status
}

// 4. Invoke coding agent
async function startCodingAgent(repoPath, task) {
  // Use execSync or spawn
  // Command: claude --workdir={repoPath} "{task}"
  // Or: codex exec --full-auto "{task}"
  // Return session ID for monitoring
}

// 5. Report back to Telegram
async function reportToTelegram(chatId, message) {
  // Send message to original chat
  // Include relevant links
}
```

## Implementation Plan

### Phase 1: Repository Creation (Core)
**Time estimate: 30 minutes**

1. Add `createProjectRepo()` function to `index.js`
2. Add `projects` table to SQLite schema
3. Add `/build [idea]` command handler
4. Test with a simple repo creation

### Phase 2: Work Queue System
**Time estimate: 30 minutes**

1. Add `work_queue` table to SQLite schema
2. Implement `queueWork()` function
3. Implement `/queue` and `/build_status` commands
4. Add periodic queue processor

### Phase 3: Coding Agent Integration
**Time estimate: 45 minutes**

1. Add `gh` CLI to safe binaries (or use http_request for GitHub API)
2. Implement `startCodingAgent()` function
3. Implement progress monitoring
4. Test with a simple scaffolding task

### Phase 4: Telegram Notifications
**Time estimate: 15 minutes**

1. Implement `reportToTelegram()` function
2. Add callbacks from work queue processor
3. Test end-to-end flow

### Phase 5: Safety & Polish
**Time estimate: 20 minutes**

1. Add rate limiting (1 repo/hour per user)
2. Add admin confirmation option
3. Add error handling and retry logic
4. Update HEARTBEAT.md with new autonomous development cycle

## Unknowns & Risks

### Open Questions

1. **Which coding agent to use?**
   - Options: `claude`, `codex`, `pi`, `opencode`
   - Claude Code requires anthropic key (already have)
   - Codex requires OpenAI key (don't have)
   - Recommendation: Use `claude` as primary

2. **Should repos be public or private?**
   - Public: Open source, visible to community
   - Private: Protected, but limits collaboration
   - Recommendation: Start with private, make public on explicit request

3. **How to handle failed builds?**
   - Retry automatically? How many times?
   - Notify user? Admin?
   - Recommendation: Retry once, then notify user and mark failed

4. **PR merge policy?**
   - Auto-merge if CI passes?
   - Require human review?
   - Recommendation: Always require human review initially

### Technical Risks

1. **`gh` CLI not in sandbox allowlist**
   - Option A: Add `gh` to safeBins (requires openclaw.json change)
   - Option B: Use GitHub REST API via `http_request` tool
   - Recommendation: Option B - more portable, already proven to work

2. **Long-running coding agent tasks**
   - 600s timeout may not be enough for complex tasks
   - Option: Break tasks into smaller chunks
   - Option: Increase timeout for specific operations

3. **Race conditions in work queue**
   - Multiple instances could pick same task
   - Mitigation: Add `locked_at` and `locked_by` columns
   - Use SQLite transactions

## Success Criteria

1. ✅ User can `/build Add a TON wallet tracker bot`
2. ✅ Bot creates `atoncap/ton-wallet-tracker` repo
3. ✅ Bot initializes with README, package.json, basic structure
4. ✅ Bot queues development work
5. ✅ Coding agent picks up task and starts working
6. ✅ PR is created with initial implementation
7. ✅ User receives Telegram notification with PR link
8. ✅ All operations are logged and trackable

## Configuration

**Confirmed settings:**
- **Ideas repo**: `alphatoncapital/ideas` - for issue tracking and idea capture
- **Build org**: `atoncap` - for actual project repositories
- **Repository visibility**: Private by default (can be made public later)
- **Auto-scaffold template**: Node.js/TypeScript (TON-friendly)
- **Admin gate**: Rate limited (1 repo/hour), no explicit approval needed
- **Coding agent**: `claude` (Anthropic key available)

---

*Plan created: 2025-02-02*
*Status: ✅ IMPLEMENTED*

## Implementation Summary

### What Was Built

1. **Repository Creation** (`createProjectRepo()`)
   - **Forks `alphatoncapital/ton-scaffolding`** into `atoncap` org
   - Renames fork to Aton-generated project name
   - Updates description and README with project details
   - Rate limited: 1 repo/hour per user
   - Sanitizes repo names (lowercase, hyphens)
   - Inherits Blueprint framework, Tact/FunC support, React dApp scaffold

2. **Database Tables**
   - `projects` - tracks created repos and their status
   - `work_queue` - async task queue for development work

3. **New Commands**
   - `/build [idea]` - Create repo and start building
   - `/projects` - List recent projects
   - `/queue` - View active work queue

4. **Work Queue Processor**
   - Clones repos to temp directory
   - Invokes Claude CLI (or API fallback)
   - Creates feature branches and PRs
   - Notifies Telegram on completion/failure

5. **Telegram Notifications**
   - Success: PR link when work completes
   - Failure: Error message with details

### How to Use

In Telegram, send:
```
/build A TON wallet tracker that shows address balances
```

Aton will:
1. Fork `alphatoncapital/ton-scaffolding` → `atoncap/ton-wallet-tracker`
2. Update README with project description
3. Queue scaffold work
4. Generate project-specific code (contracts, dApp)
5. Create a PR for review
6. Notify you when done
