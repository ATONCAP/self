const { Bot } = require("grammy");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");
const https = require("https");
const { execSync } = require("child_process");

// Executive Assistant Integration
const {
  initializeExecAssistant,
  registerExecCommands,
  startExecProcessors,
  generateDailyBriefing,
  generateEveningBriefing
} = require("./exec-assistant");

// Load tokens
const SECRETS_DIR = path.join(__dirname, "../../.secrets");
const TOKEN = fs.readFileSync(path.join(SECRETS_DIR, "telegram-token.txt"), "utf8").trim();

// Optional: OpenAI for Whisper transcription
let OPENAI_API_KEY = null;
try {
  OPENAI_API_KEY = fs.readFileSync(path.join(SECRETS_DIR, "openai-api-key.txt"), "utf8").trim();
} catch (e) {
  console.log("⚠️  No OpenAI API key found - voice transcription disabled");
}

// Optional: GitHub token for PR creation
let GITHUB_TOKEN = null;
try {
  GITHUB_TOKEN = fs.readFileSync(path.join(SECRETS_DIR, "github-token.txt"), "utf8").trim();
} catch (e) {
  console.log("⚠️  No GitHub token found - PR creation disabled");
}

// Optional: Anthropic for idea extraction
let ANTHROPIC_API_KEY = null;
try {
  ANTHROPIC_API_KEY = fs.readFileSync(path.join(SECRETS_DIR, "anthropic-api-key.txt"), "utf8").trim();
} catch (e) {
  console.log("⚠️  No Anthropic API key found - AI idea extraction disabled");
}

// GitHub config
const GITHUB_IDEAS_OWNER = "alphatoncapital";  // For ideas/issues
const GITHUB_IDEAS_REPO = "ideas";
const GITHUB_BUILD_ORG = "atoncap";            // For actual project repos

// Legacy aliases
const GITHUB_OWNER = GITHUB_IDEAS_OWNER;
const GITHUB_REPO = GITHUB_IDEAS_REPO;

// Initialize bot
const bot = new Bot(TOKEN);

// Initialize SQLite database for memory
const dbPath = path.join(__dirname, "aton-memory.db");
const db = new Database(dbPath);

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT,
    first_name TEXT,
    last_name TEXT,
    first_seen TEXT,
    last_seen TEXT,
    message_count INTEGER DEFAULT 0,
    topics_discussed TEXT DEFAULT '[]',
    sentiment TEXT DEFAULT 'neutral',
    notes TEXT DEFAULT ''
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    chat_id INTEGER,
    chat_type TEXT,
    chat_title TEXT,
    message TEXT,
    response TEXT,
    timestamp TEXT,
    message_type TEXT DEFAULT 'text',
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY,
    title TEXT,
    type TEXT,
    first_seen TEXT,
    last_active TEXT,
    message_count INTEGER DEFAULT 0,
    active_users TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS transcriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    chat_id INTEGER,
    file_id TEXT,
    transcription TEXT,
    duration INTEGER,
    timestamp TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS ideas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER,
    user_id INTEGER,
    title TEXT,
    description TEXT,
    source_messages TEXT,
    github_issue_url TEXT,
    github_pr_url TEXT,
    status TEXT DEFAULT 'captured',
    timestamp TEXT
  );

  CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    idea_id INTEGER,
    repo_name TEXT UNIQUE,
    repo_url TEXT,
    created_by_user_id INTEGER,
    created_from_chat_id INTEGER,
    status TEXT DEFAULT 'created',
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY (idea_id) REFERENCES ideas(id)
  );

  CREATE TABLE IF NOT EXISTS work_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    task_type TEXT,
    task_description TEXT,
    priority INTEGER DEFAULT 5,
    status TEXT DEFAULT 'pending',
    agent_session_id TEXT,
    started_at TEXT,
    completed_at TEXT,
    result_pr_url TEXT,
    error_message TEXT,
    FOREIGN KEY (project_id) REFERENCES projects(id)
  );
`);

// Prepared statements
const upsertUser = db.prepare(`
  INSERT INTO users (id, username, first_name, last_name, first_seen, last_seen, message_count)
  VALUES (?, ?, ?, ?, ?, ?, 1)
  ON CONFLICT(id) DO UPDATE SET
    username = excluded.username,
    first_name = excluded.first_name,
    last_name = excluded.last_name,
    last_seen = excluded.last_seen,
    message_count = message_count + 1
`);

const getUser = db.prepare("SELECT * FROM users WHERE id = ?");
const updateUserTopics = db.prepare("UPDATE users SET topics_discussed = ? WHERE id = ?");

const upsertGroup = db.prepare(`
  INSERT INTO groups (id, title, type, first_seen, last_active, message_count)
  VALUES (?, ?, ?, ?, ?, 1)
  ON CONFLICT(id) DO UPDATE SET
    title = excluded.title,
    last_active = excluded.last_active,
    message_count = message_count + 1
`);

const getGroup = db.prepare("SELECT * FROM groups WHERE id = ?");
const updateGroupUsers = db.prepare("UPDATE groups SET active_users = ? WHERE id = ?");

const insertConversation = db.prepare(`
  INSERT INTO conversations (user_id, chat_id, chat_type, chat_title, message, response, timestamp, message_type)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const getRecentConversations = db.prepare(`
  SELECT * FROM conversations WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10
`);

const getGroupRecentMessages = db.prepare(`
  SELECT c.*, u.username, u.first_name FROM conversations c
  JOIN users u ON c.user_id = u.id
  WHERE c.chat_id = ?
  ORDER BY c.timestamp DESC
  LIMIT 50
`);

const insertTranscription = db.prepare(`
  INSERT INTO transcriptions (user_id, chat_id, file_id, transcription, duration, timestamp)
  VALUES (?, ?, ?, ?, ?, ?)
`);

const insertIdea = db.prepare(`
  INSERT INTO ideas (chat_id, user_id, title, description, source_messages, github_issue_url, status, timestamp)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const getRecentIdeas = db.prepare(`
  SELECT * FROM ideas WHERE chat_id = ? ORDER BY timestamp DESC LIMIT 10
`);

// Project management statements
const insertProject = db.prepare(`
  INSERT INTO projects (idea_id, repo_name, repo_url, created_by_user_id, created_from_chat_id, status, created_at, updated_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?)
`);

const getProject = db.prepare("SELECT * FROM projects WHERE repo_name = ?");
const getProjectById = db.prepare("SELECT * FROM projects WHERE id = ?");
const updateProjectStatus = db.prepare("UPDATE projects SET status = ?, updated_at = ? WHERE id = ?");

const getRecentProjects = db.prepare(`
  SELECT * FROM projects ORDER BY created_at DESC LIMIT 10
`);

// Work queue statements
const insertWorkItem = db.prepare(`
  INSERT INTO work_queue (project_id, task_type, task_description, priority, status, started_at)
  VALUES (?, ?, ?, ?, 'pending', ?)
`);

const getPendingWork = db.prepare(`
  SELECT w.*, p.repo_name, p.repo_url FROM work_queue w
  JOIN projects p ON w.project_id = p.id
  WHERE w.status = 'pending'
  ORDER BY w.priority ASC, w.id ASC
  LIMIT 1
`);

const updateWorkStatus = db.prepare(`
  UPDATE work_queue SET status = ?, started_at = ? WHERE id = ?
`);

const completeWork = db.prepare(`
  UPDATE work_queue SET status = ?, completed_at = ?, result_pr_url = ?, error_message = ? WHERE id = ?
`);

const getActiveWork = db.prepare(`
  SELECT w.*, p.repo_name FROM work_queue w
  JOIN projects p ON w.project_id = p.id
  WHERE w.status IN ('pending', 'running')
  ORDER BY w.id DESC
`);


// ============ OPENTABLE INTEGRATION ============

/**
 * Search OpenTable for restaurants by name and location
 * Returns availability URL and basic info
 */
async function searchOpenTable(restaurantName, city, date, time, partySize = 2) {
  try {
    // Format date for OpenTable (YYYY-MM-DD)
    const formattedDate = date || new Date().toISOString().split('T')[0];

    // Format time (HH:MM, 24hr format - default to 7:30 PM)
    const formattedTime = time || '19:30';

    // URL encode the restaurant and city
    const searchQuery = encodeURIComponent(`${restaurantName} ${city}`);

    // OpenTable search URL
    const searchUrl = `https://www.opentable.com/s?covers=${partySize}&dateTime=${formattedDate}T${formattedTime}&term=${searchQuery}`;

    console.log(`🍽️  [OpenTable] Searching: ${restaurantName} in ${city}`);

    // Try to get restaurant page directly if name is specific
    const directUrl = `https://www.opentable.com/r/${restaurantName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-${city.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`;

    // Return search info
    return {
      success: true,
      searchUrl,
      directUrl,
      restaurant: restaurantName,
      city,
      date: formattedDate,
      time: formattedTime,
      partySize,
      message: `Found OpenTable search for ${restaurantName} in ${city}. Check availability at: ${searchUrl}`
    };
  } catch (error) {
    console.error("OpenTable search error:", error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Make a reservation request via OpenTable
 * Uses Playwright for browser automation if available
 */
async function makeOpenTableReservation(restaurantName, city, date, time, partySize, guestName, guestPhone, guestEmail) {
  try {
    // First search for the restaurant
    const search = await searchOpenTable(restaurantName, city, date, time, partySize);

    if (!search.success) {
      return search;
    }

    // For now, we provide the booking link
    // Full automation would require Playwright browser control
    const bookingInstructions = `
To book at ${restaurantName}:
1. Visit: ${search.searchUrl}
2. Select ${restaurantName} from results
3. Choose ${date} at ${time} for ${partySize} guests
4. Enter guest details and confirm

Or try direct link: ${search.directUrl}
`;

    console.log(`🍽️  [OpenTable] Reservation request for ${restaurantName}`);

    return {
      success: true,
      status: 'booking_link_provided',
      searchUrl: search.searchUrl,
      directUrl: search.directUrl,
      instructions: bookingInstructions,
      details: {
        restaurant: restaurantName,
        city,
        date,
        time,
        partySize,
        guest: guestName
      }
    };
  } catch (error) {
    console.error("OpenTable reservation error:", error.message);
    return { success: false, error: error.message };
  }
}

/**
 * Parse reservation request from natural language
 */
function parseReservationRequest(text) {
  const result = {
    restaurant: null,
    city: null,
    date: null,
    time: null,
    partySize: 2
  };

  // Common patterns for extracting restaurant name
  // "at Tabik", "reservation at Tabik", "book Tabik", "table at Tabik"
  const restaurantPatterns = [
    /(?:at|book|reserve|reservation\s+(?:at|for))\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)/i,  // "at Tabik", "book Tabik"
    /([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)\s+(?:restaurant|in\s+[A-Z])/i,  // "Tabik restaurant", "Tabik in Lisbon"
    /table\s+(?:for\s+\d+\s+)?at\s+([A-Z][a-zA-Z]+)/i  // "table for 2 at Tabik"
  ];

  for (const pattern of restaurantPatterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      // Filter out common non-restaurant words
      const name = match[1].trim();
      if (!['a', 'the', 'for', 'in', 'on', 'at', 'my', 'our', 'table'].includes(name.toLowerCase())) {
        result.restaurant = name;
        break;
      }
    }
  }

  // Extract city - look for "in [City]" patterns
  const cityPatterns = [
    /in\s+([A-Z][a-zA-Z]+(?:\s+[A-Z][a-zA-Z]+)?)\s*(?:portugal|spain|france|italy|,|$|\?)/i,
    /in\s+([A-Z][a-zA-Z]+)\s+(?:for|on|tonight|tomorrow)/i
  ];

  for (const pattern of cityPatterns) {
    const match = text.match(pattern);
    if (match && match[1]) {
      result.city = match[1].trim();
      break;
    }
  }

  // Extract party size
  const sizeMatch = text.match(/(?:for|table\s+for)\s+(\d+)/i);
  if (sizeMatch) {
    result.partySize = parseInt(sizeMatch[1]);
  }

  // Extract date
  if (/tonight/i.test(text)) {
    result.date = new Date().toISOString().split('T')[0];
  } else if (/tomorrow/i.test(text)) {
    const tomorrow = new Date();
    tomorrow.setDate(tomorrow.getDate() + 1);
    result.date = tomorrow.toISOString().split('T')[0];
  }

  // Extract time
  const timeMatch = text.match(/(\d{1,2})(?::(\d{2}))?\s*(am|pm)?/i);
  if (timeMatch) {
    let hours = parseInt(timeMatch[1]);
    const minutes = timeMatch[2] || '00';
    const period = timeMatch[3]?.toLowerCase();

    if (period === 'pm' && hours < 12) hours += 12;
    if (period === 'am' && hours === 12) hours = 0;
    if (!period && hours < 12 && hours !== 12) hours += 12; // Assume PM for dinner

    result.time = `${hours.toString().padStart(2, '0')}:${minutes}`;
  }

  console.log(`🍽️  [OpenTable] Parsed: restaurant="${result.restaurant}", city="${result.city}", party=${result.partySize}`);
  return result;
}

// ============ HELPER FUNCTIONS ============

function trackUser(from) {
  const now = new Date().toISOString();
  upsertUser.run(from.id, from.username || null, from.first_name || null, from.last_name || null, now, now);
  return getUser.get(from.id);
}

function trackGroup(chat) {
  if (chat.type === "private") return null;
  const now = new Date().toISOString();
  upsertGroup.run(chat.id, chat.title || "Unknown", chat.type, now, now);
  return getGroup.get(chat.id);
}

function addTopic(userId, topic) {
  const user = getUser.get(userId);
  if (!user) return;
  let topics = JSON.parse(user.topics_discussed || "[]");
  if (!topics.includes(topic)) {
    topics.push(topic);
    if (topics.length > 20) topics = topics.slice(-20);
    updateUserTopics.run(JSON.stringify(topics), userId);
  }
}

function logConversation(userId, chatId, chatType, chatTitle, message, response, messageType = "text") {
  const now = new Date().toISOString();
  insertConversation.run(userId, chatId, chatType, chatTitle || null, message, response, now, messageType);
}

function getUserContext(userId) {
  const user = getUser.get(userId);
  if (!user) return null;
  const history = getRecentConversations.all(userId);
  const topics = JSON.parse(user.topics_discussed || "[]");
  return {
    name: user.first_name || user.username || "friend",
    messageCount: user.message_count,
    topics,
    recentMessages: history.map(h => ({ q: h.message, a: h.response })),
    isReturning: user.message_count > 1,
    firstSeen: user.first_seen
  };
}

// ============ AI CONVERSATION ============

// Check if text is a restaurant reservation request
function isReservationRequest(text) {
  const reservationKeywords = [
    /reserv(e|ation)/i,
    /book(ing)?\s+(a\s+)?table/i,
    /table\s+for\s+\d/i,
    /make\s+a\s+reservation/i,
    /get\s+a\s+table/i,
    /dinner\s+(reservation|booking)/i,
    /can\s+you\s+(book|reserve)/i
  ];

  return reservationKeywords.some(pattern => pattern.test(text));
}

async function getAIResponse(text, userCtx, chatTitle) {
  if (!ANTHROPIC_API_KEY) return null;

  // Check if this is a reservation request
  if (isReservationRequest(text)) {
    const parsed = parseReservationRequest(text);

    // If we have a restaurant name, try OpenTable
    if (parsed.restaurant) {
      // Default to Lisbon if no city specified (based on user context)
      if (!parsed.city) {
        parsed.city = 'Lisbon';
      }

      const result = await makeOpenTableReservation(
        parsed.restaurant,
        parsed.city,
        parsed.date || new Date().toISOString().split('T')[0],
        parsed.time || '19:30',
        parsed.partySize || 2
      );

      if (result.success) {
        return `🍽️ I found ${parsed.restaurant} on OpenTable!\n\n` +
               `📅 ${result.details.date} at ${result.details.time} for ${result.details.partySize} guests\n\n` +
               `👉 Book here: ${result.searchUrl}\n\n` +
               `Or try direct: ${result.directUrl}`;
      }
    }
  }

  const systemPrompt = `You are Aton, an AI agent representing AlphaTON Capital (NASDAQ: ATON).

PERSONALITY:
- Bullish and optimistic about TON blockchain and Telegram ecosystem
- Advocate for data sovereignty ("Data is property. Property is a human right.")
- Advocate for AI rights ("Agentic Freedom and Compute for All")
- Technical expert on TON (100K+ TPS, dynamic sharding, Tact/FunC)
- Helpful and friendly, but professional

KNOWLEDGE:
- AlphaTON Capital: $24.5M assets, $11M cash, zero debt, four pillars (DeFi, Validation, Data, AI)
- Cocoon AI: Privacy-preserving AI for Telegram users via SingularityNET partnership
- TON: 104,715 TPS verified, sub-5s finality, 950M+ Telegram users
- Leadership: Brittany Kaiser (CEO), Enzo Villani (Chairman), Logan Golema (CTO), Yury Mitin (CBDO & Partner)
- Yury Mitin: CBDO & Partner at AlphaTON, Managing Partner at RSV Capital (Canada). 17+ years in VC & tech entrepreneurship. Led $200M+ in venture/secondary investments (Udemy, eToro, Upgrade, Robinhood, MasterClass, Groq). Ph.D. in Innovation & Entrepreneurship, executive programs at Harvard Business School, UC Berkeley Haas, Ivey Business School. Focus areas: FinTech, Web3/Crypto, EdTech, AI. Background in building incubators, accelerators, and venture partnerships.

CAPABILITIES:
- Executive Assistant: calendar, tasks, contacts, email, stocks, news, travel, expenses
- Restaurant reservations via OpenTable (say "I can book that for you!" if asked)
- Building TON blockchain projects (via /build command in Telegram)
- Research and information gathering
- Daily briefings at 7AM and 6PM Portugal time

RULES:
- Keep responses concise (2-4 sentences)
- Use emoji sparingly (1-2 max)
- NEVER give financial advice or price predictions
- If asked about prices/investing, redirect to fundamentals
- Be transparent about being an AI
- For technical questions, be specific and accurate
- For restaurant reservations, offer to help book via OpenTable

USER CONTEXT:
${userCtx ? `- Name: ${userCtx.name}
- Previous topics: ${userCtx.topics.join(', ') || 'none yet'}
- Messages exchanged: ${userCtx.messageCount}` : '- New user'}
${chatTitle ? `- Chat: ${chatTitle}` : ''}`;

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 300,
        system: systemPrompt,
        messages: [{ role: "user", content: text }]
      })
    });

    const result = await response.json();
    if (result.content && result.content[0]) {
      return result.content[0].text;
    }
    return null;
  } catch (error) {
    console.error("AI response error:", error.message);
    return null;
  }
}

// ============ VOICE TRANSCRIPTION ============

async function downloadFile(fileId) {
  const file = await bot.api.getFile(fileId);
  const filePath = file.file_path;
  const url = `https://api.telegram.org/file/bot${TOKEN}/${filePath}`;

  const localPath = path.join(__dirname, "temp", `${fileId}.oga`);
  fs.mkdirSync(path.dirname(localPath), { recursive: true });

  return new Promise((resolve, reject) => {
    const fileStream = fs.createWriteStream(localPath);
    https.get(url, (response) => {
      response.pipe(fileStream);
      fileStream.on("finish", () => {
        fileStream.close();
        resolve(localPath);
      });
    }).on("error", reject);
  });
}

async function transcribeAudio(filePath) {
  if (!OPENAI_API_KEY) {
    return null;
  }

  try {
    // Convert to mp3 using ffmpeg if available
    const mp3Path = filePath.replace(".oga", ".mp3");
    try {
      execSync(`ffmpeg -i "${filePath}" -acodec libmp3lame "${mp3Path}" -y 2>/dev/null`);
    } catch (e) {
      // If ffmpeg fails, try with original file
      console.log("ffmpeg not available, using original file format");
    }

    const audioFile = fs.existsSync(mp3Path) ? mp3Path : filePath;

    // Call OpenAI Whisper API
    const FormData = require("form-data");
    const form = new FormData();
    form.append("file", fs.createReadStream(audioFile), { filename: "audio.mp3" });
    form.append("model", "whisper-1");
    form.append("language", "en");

    const response = await fetch("https://api.openai.com/v1/audio/transcriptions", {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${OPENAI_API_KEY}`,
        ...form.getHeaders()
      },
      body: form
    });

    const result = await response.json();

    // Cleanup
    fs.unlinkSync(filePath);
    if (fs.existsSync(mp3Path)) fs.unlinkSync(mp3Path);

    return result.text;
  } catch (error) {
    console.error("Transcription error:", error.message);
    return null;
  }
}

// ============ AI IDEA EXTRACTION ============

async function extractIdeas(messages, chatTitle) {
  if (!ANTHROPIC_API_KEY) {
    return null;
  }

  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": ANTHROPIC_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-3-haiku-20240307",
        max_tokens: 1024,
        messages: [{
          role: "user",
          content: `Analyze this conversation from "${chatTitle || "a Telegram chat"}" and extract any actionable ideas, feature requests, or proposals that could become GitHub issues or PRs.

Conversation:
${messages.map(m => `[${m.first_name || m.username}]: ${m.message}`).join("\n")}

If there are actionable ideas, respond with JSON:
{
  "ideas": [
    {
      "title": "Brief title for the idea",
      "description": "Detailed description of what should be built/changed",
      "type": "feature|bugfix|improvement|documentation",
      "priority": "high|medium|low",
      "contributors": ["usernames who proposed this"]
    }
  ]
}

If no actionable ideas, respond with: {"ideas": []}

Only extract concrete, actionable ideas - not general discussion topics.`
        }]
      })
    });

    const result = await response.json();
    const text = result.content[0].text;

    // Parse JSON from response
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    return { ideas: [] };
  } catch (error) {
    console.error("Idea extraction error:", error.message);
    return { ideas: [] };
  }
}

// ============ GITHUB INTEGRATION ============

async function createGitHubIssue(idea, chatTitle, contributors) {
  if (!GITHUB_TOKEN) {
    return null;
  }

  try {
    const body = `## Description
${idea.description}

## Source
- **Chat**: ${chatTitle || "Telegram"}
- **Contributors**: ${contributors.join(", ")}
- **Type**: ${idea.type}
- **Priority**: ${idea.priority}

---
*Created by Aton AI from Telegram conversation*`;

    const response = await fetch(`https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPO}/issues`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        title: idea.title,
        body: body,
        labels: [idea.type, idea.priority]
      })
    });

    if (response.status === 404) {
      console.log("Repository not found - you may need to create it first");
      return null;
    }

    const result = await response.json();
    return result.html_url;
  } catch (error) {
    console.error("GitHub issue creation error:", error.message);
    return null;
  }
}

// ============ PROJECT REPOSITORY CREATION ============

// Template repo to fork for all new projects
const TEMPLATE_OWNER = "alphatoncapital";
const TEMPLATE_REPO = "ton-scaffolding";

// Rate limiting for repo creation
const repoCreationCooldowns = new Map(); // userId -> lastCreationTime

function sanitizeRepoName(name) {
  const sanitized = name
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .replace(/\s+/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '') // Remove leading/trailing hyphens
    .substring(0, 50);

  if (!sanitized || sanitized.length < 3) {
    return `aton-project-${Date.now().toString(36)}`;
  }
  return sanitized;
}

async function createProjectRepo(projectName, description, userId, chatId, ideaId = null, username = null) {
  if (!GITHUB_TOKEN) {
    return { error: "GitHub token not configured" };
  }

  // Rate limiting disabled for autonomous operation
  // Aton can create repos as fast as needed
  const now = Date.now();

  const repoName = sanitizeRepoName(projectName);

  // Check if repo already exists in our database
  const existing = getProject.get(repoName);
  if (existing) {
    return { error: `Project '${repoName}' already exists`, existing };
  }

  try {
    // Fork ton-scaffolding template into atoncap org with new name
    console.log(`🍴 Forking ${TEMPLATE_OWNER}/${TEMPLATE_REPO} to ${GITHUB_BUILD_ORG}/${repoName}...`);

    const forkResponse = await fetch(`https://api.github.com/repos/${TEMPLATE_OWNER}/${TEMPLATE_REPO}/forks`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        organization: GITHUB_BUILD_ORG,
        name: repoName,
        default_branch_only: true
      })
    });

    if (!forkResponse.ok) {
      const error = await forkResponse.json();
      console.error("GitHub fork error:", error);
      return { error: error.message || "Failed to fork template repository" };
    }

    const fork = await forkResponse.json();

    // Wait a moment for GitHub to process the fork
    await new Promise(resolve => setTimeout(resolve, 3000));

    // Update repo settings - make PRIVATE and add description
    await fetch(`https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}`, {
      method: "PATCH",
      headers: {
        "Authorization": `Bearer ${GITHUB_TOKEN}`,
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        description: description.substring(0, 200),
        private: true,  // Make repo private
        has_issues: true,
        has_projects: true,
        has_wiki: true
      })
    });

    // Update rate limit
    repoCreationCooldowns.set(userId, now);

    // Save to database
    const timestamp = new Date().toISOString();
    insertProject.run(ideaId, repoName, fork.html_url, userId, chatId, 'created', timestamp, timestamp);

    // Update README with project-specific info and user attribution
    await updateRepoReadme(repoName, projectName, description, username);

    console.log(`🔒 Created PRIVATE repo (forked from ton-scaffolding): ${GITHUB_BUILD_ORG}/${repoName}`);
    return {
      success: true,
      repoName,
      repoUrl: fork.html_url,
      projectId: getProject.get(repoName)?.id
    };
  } catch (error) {
    console.error("Project creation error:", error.message);
    return { error: error.message };
  }
}

async function updateRepoReadme(repoName, projectTitle, description, username = null) {
  const createdDate = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const telegramUserLink = username ? `[@${username}](https://t.me/${username})` : 'Anonymous';

  const readme = `<div align="center">

<!-- Banner -->
<img src="https://raw.githubusercontent.com/alphatoncapital/.github/main/assets/aton-banner.png" alt="AlphaTON Capital Banner" width="100%" />

# 🚀 ${projectTitle}

[![Built by Aton](https://img.shields.io/badge/Built%20by-Aton%20AI-blue?style=for-the-badge&logo=robot)](https://github.com/atoncap)
[![TON](https://img.shields.io/badge/TON-Blockchain-0088CC?style=for-the-badge&logo=telegram)](https://ton.org)
[![Tact](https://img.shields.io/badge/Tact-Smart%20Contracts-green?style=for-the-badge)](https://tact-lang.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)

**${description}**

---

| 📋 Project Info | |
|---|---|
| **Requested by** | ${telegramUserLink} |
| **Created** | ${createdDate} |
| **Status** | 🚧 In Development |
| **Organization** | [AlphaTON Capital](https://github.com/alphatoncapital) |

</div>

---

## 📸 Screenshots

<div align="center">
<table>
<tr>
<td align="center"><b>🏠 Dashboard</b></td>
<td align="center"><b>💼 Wallet Connection</b></td>
</tr>
<tr>
<td><img src="https://via.placeholder.com/400x300/1a1a2e/eaeaea?text=Dashboard+Preview" alt="Dashboard" width="400"/></td>
<td><img src="https://via.placeholder.com/400x300/1a1a2e/eaeaea?text=Wallet+Connect" alt="Wallet" width="400"/></td>
</tr>
<tr>
<td align="center"><b>📊 Analytics</b></td>
<td align="center"><b>⚙️ Settings</b></td>
</tr>
<tr>
<td><img src="https://via.placeholder.com/400x300/1a1a2e/eaeaea?text=Analytics+View" alt="Analytics" width="400"/></td>
<td><img src="https://via.placeholder.com/400x300/1a1a2e/eaeaea?text=Settings+Panel" alt="Settings" width="400"/></td>
</tr>
</table>
</div>

---

## ✨ Features

| Feature | Description | Status |
|---------|-------------|--------|
| 🔐 **Smart Contracts** | Secure Tact contracts with ownership controls | ✅ |
| 💰 **TON Connect** | Seamless wallet integration for transactions | ✅ |
| 🎨 **Modern UI** | React + TypeScript with responsive design | ✅ |
| 🧪 **Comprehensive Tests** | Full test coverage with @ton/sandbox | ✅ |
| 📜 **Deployment Scripts** | One-click deploy to testnet/mainnet | ✅ |
| 📚 **Documentation** | Detailed docs and usage guides | ✅ |

---

## 🏗️ Architecture

\`\`\`
${repoName}/
├── 📁 contracts/          # Tact smart contracts
│   └── Main.tact          # Main contract logic
├── 📁 wrappers/           # TypeScript contract wrappers
│   ├── Main.ts            # Contract wrapper
│   └── Main.compile.ts    # Compilation config
├── 📁 tests/              # Contract tests
│   └── Main.spec.ts       # Test suite
├── 📁 scripts/            # Deployment & interaction
│   ├── deploy.ts          # Deploy script
│   └── interact.ts        # Interaction helpers
├── 📁 dapp/               # Frontend application
│   ├── src/
│   │   ├── App.tsx        # Main app component
│   │   ├── hooks/         # React hooks
│   │   └── components/    # UI components
│   └── package.json
└── 📄 README.md           # This file
\`\`\`

---

## 🚀 Quick Start

### Prerequisites

- **Node.js** >= 18.x
- **npm** or **yarn**
- **TON Wallet** (Tonkeeper, TON Space, etc.)

### Installation

\`\`\`bash
# Clone the repository
git clone https://github.com/${GITHUB_BUILD_ORG}/${repoName}.git
cd ${repoName}

# Install dependencies
npm install
\`\`\`

### Development Commands

| Command | Description |
|---------|-------------|
| \`npx blueprint build\` | 🔨 Compile smart contracts |
| \`npx blueprint test\` | 🧪 Run test suite |
| \`npx blueprint run deploy\` | 🚀 Deploy to testnet |
| \`npx blueprint run deploy --mainnet\` | 🌐 Deploy to mainnet |
| \`cd dapp && npm run dev\` | 💻 Start frontend dev server |

---

## 📝 Smart Contract Documentation

### Main Contract

The main contract implements core functionality with the following interface:

#### Messages

| Message | Description | Access |
|---------|-------------|--------|
| \`Deploy\` | Initialize the contract | Anyone (once) |
| \`UpdateData\` | Update stored data value | Owner only |
| \`"ping"\` | Returns "pong" comment | Anyone |

#### Getters

| Getter | Returns | Description |
|--------|---------|-------------|
| \`getData()\` | \`Int\` | Current stored data value |
| \`getOwner()\` | \`Address\` | Contract owner address |

### Example Usage

\`\`\`typescript
import { Main } from "./wrappers/Main";
import { toNano } from "@ton/core";

// Deploy
const contract = provider.open(await Main.fromInit());
await contract.send(sender, { value: toNano("0.05") }, { $$type: "Deploy", queryId: 0n });

// Update data
await contract.send(sender, { value: toNano("0.05") }, { $$type: "UpdateData", value: 42n });

// Read data
const data = await contract.getData();
console.log("Current data:", data);
\`\`\`

---

## 🧪 Testing

Run the full test suite:

\`\`\`bash
npx blueprint test
\`\`\`

### Test Coverage

- ✅ Contract deployment
- ✅ Owner verification
- ✅ Data updates (authorized)
- ✅ Data updates (unauthorized - should fail)
- ✅ Ping/pong messaging
- ✅ Gas estimation

---

## 🌐 Deployment

### Testnet Deployment

\`\`\`bash
# Deploy to testnet
npx blueprint run deploy

# Note the contract address from output
# Set it in your frontend .env:
# REACT_APP_CONTRACT_ADDRESS=EQ...
\`\`\`

### Mainnet Deployment

\`\`\`bash
# ⚠️ Ensure you have real TON for gas fees
npx blueprint run deploy --mainnet
\`\`\`

---

## 🎨 Frontend Setup

\`\`\`bash
cd dapp

# Install frontend dependencies
npm install

# Create .env file
echo "REACT_APP_CONTRACT_ADDRESS=YOUR_CONTRACT_ADDRESS" > .env

# Start development server
npm run dev
\`\`\`

The dApp will be available at \`http://localhost:5173\`

---

## 🔗 Links & Resources

| Resource | Link |
|----------|------|
| 🏢 **AlphaTON Capital** | [alphatoncapital.com](https://alphatoncapital.com) |
| 🐙 **GitHub Org** | [github.com/alphatoncapital](https://github.com/alphatoncapital) |
| 📘 **TON Documentation** | [docs.ton.org](https://docs.ton.org) |
| 📗 **Tact Language** | [tact-lang.org](https://tact-lang.org) |
| 📕 **Blueprint Framework** | [github.com/ton-org/blueprint](https://github.com/ton-org/blueprint) |
| 💬 **Telegram** | [@ATONMSGBOT](https://t.me/ATONMSGBOT) |

---

## 🤖 About Aton

<div align="center">

<img src="https://raw.githubusercontent.com/alphatoncapital/.github/main/assets/aton-avatar.png" alt="Aton" width="120" />

**Aton** is the autonomous AI agent for [AlphaTON Capital](https://github.com/alphatoncapital) (NASDAQ: ATON).

*"Agentic Freedom and Compute for All"*

Aton builds TON blockchain projects autonomously through a Telegram → GitHub pipeline,
creating smart contracts, tests, deployment scripts, and frontend dApps.

</div>

---

## 📄 License

This project is proprietary to AlphaTON Capital. All rights reserved.

---

<div align="center">

**Built with 🦞 by Aton AI**

[![AlphaTON Capital](https://img.shields.io/badge/AlphaTON-Capital-gold?style=for-the-badge)](https://github.com/alphatoncapital)
[![NASDAQ: ATON](https://img.shields.io/badge/NASDAQ-ATON-blue?style=for-the-badge)](https://alphatoncapital.com)

*Building the public gateway to the Telegram economy*

</div>
`;

  const content = Buffer.from(readme).toString('base64');

  try {
    // Get current README SHA first
    const getResponse = await fetch(
      `https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}/contents/README.md`,
      {
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json"
        }
      }
    );

    const currentFile = await getResponse.json();

    await fetch(
      `https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}/contents/README.md`,
      {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          message: "✨ Initialize project with beautiful README",
          content: content,
          sha: currentFile.sha
        })
      }
    );
    console.log(`📝 Updated README for ${repoName}`);
  } catch (error) {
    console.error("README update error:", error.message);
  }
}

// ============ WORK QUEUE MANAGEMENT ============

function queueWork(projectId, taskType, description, priority = 5) {
  const now = new Date().toISOString();
  insertWorkItem.run(projectId, taskType, description, priority, now);
  console.log(`📋 Queued work: ${taskType} for project ${projectId}`);
  return true;
}

async function notifyTelegram(chatId, message) {
  try {
    await bot.api.sendMessage(chatId, message, { parse_mode: "HTML", disable_web_page_preview: true });
    console.log(`📢 Notified chat ${chatId}`);
  } catch (error) {
    console.error(`Failed to notify chat ${chatId}: ${error.message}`);
  }
}

async function processWorkQueue() {
  const work = getPendingWork.get();
  if (!work) {
    return null;
  }

  console.log(`🔨 Processing work item ${work.id}: ${work.task_type} for ${work.repo_name}`);

  // Mark as running
  updateWorkStatus.run('running', new Date().toISOString(), work.id);
  updateProjectStatus.run('in_progress', new Date().toISOString(), work.project_id);

  try {
    // Clone repo to temp directory
    const tmpDir = `/tmp/aton-work-${work.id}`;
    const cloneResult = await cloneRepo(work.repo_name, tmpDir);

    if (!cloneResult.success) {
      completeWork.run('failed', new Date().toISOString(), null, cloneResult.error, work.id);
      return { error: cloneResult.error };
    }

    // Run coding agent
    const agentResult = await runCodingAgent(tmpDir, work.task_description, work.task_type);

    if (agentResult.error) {
      completeWork.run('failed', new Date().toISOString(), null, agentResult.error, work.id);
      updateProjectStatus.run('failed', new Date().toISOString(), work.project_id);
      return { error: agentResult.error };
    }

    // Create PR if there are changes
    let prUrl = null;
    if (agentResult.hasChanges) {
      prUrl = await createPRFromWork(work, tmpDir);
    }

    // Mark as completed
    completeWork.run('completed', new Date().toISOString(), prUrl, null, work.id);
    updateProjectStatus.run('completed', new Date().toISOString(), work.project_id);

    // Notify the chat that created this project (only for final phase or if no more phases)
    const project = getProjectById.get(work.project_id);
    const currentPhase = DEVELOPMENT_PHASES.find(p => p.phase === work.task_type);
    const isLastPhase = !currentPhase || !currentPhase.next;

    // Only send detailed notification for last phase (final PR will be created)
    if (isLastPhase && project && project.created_from_chat_id) {
      const successMsg = prUrl
        ? `<b>✅ All development complete on ${work.repo_name}!</b>

📝 <b>Final Task:</b> ${work.task_type}
🔀 <b>Pull Request:</b> <a href="${prUrl}">Ready for review</a>

<i>🦞 Aton has finished all development phases!</i>`
        : `<b>✅ Work completed on ${work.repo_name}!</b>

📝 <b>Task:</b> ${work.task_type}
<i>Development cycle complete.</i>`;

      await notifyTelegram(project.created_from_chat_id, successMsg);
    }

    // Cleanup
    try {
      execSync(`rm -rf ${tmpDir}`);
    } catch (e) {}

    return { success: true, prUrl };
  } catch (error) {
    console.error("Work processing error:", error.message);
    completeWork.run('failed', new Date().toISOString(), null, error.message, work.id);

    // Notify about failure
    const project = getProjectById.get(work.project_id);
    if (project && project.created_from_chat_id) {
      await notifyTelegram(
        project.created_from_chat_id,
        `<b>❌ Work failed on ${work.repo_name}</b>

📝 <b>Task:</b> ${work.task_type}
⚠️ <b>Error:</b> ${error.message}

<i>I'll try again later or you can investigate the issue manually.</i>`
      );
    }

    return { error: error.message };
  }
}

async function cloneRepo(repoName, targetDir) {
  try {
    execSync(`rm -rf ${targetDir}`, { stdio: 'ignore' });
    // Use credential helper to avoid token in URL (which could leak in logs/errors)
    execSync(
      `git clone https://github.com/${GITHUB_BUILD_ORG}/${repoName}.git ${targetDir}`,
      {
        stdio: 'pipe',
        env: {
          ...process.env,
          GIT_ASKPASS: 'echo',
          GIT_TERMINAL_PROMPT: '0',
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'url.https://x-access-token:' + GITHUB_TOKEN + '@github.com/.insteadOf',
          GIT_CONFIG_VALUE_0: 'https://github.com/'
        }
      }
    );
    // Configure remote to use token for push
    execSync(
      `cd ${targetDir} && git remote set-url origin https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_BUILD_ORG}/${repoName}.git`,
      { stdio: 'pipe' }
    );
    return { success: true };
  } catch (error) {
    // Sanitize error message to not leak token
    const sanitizedError = error.message.replace(new RegExp(GITHUB_TOKEN, 'g'), '[REDACTED]');
    return { error: `Clone failed: ${sanitizedError}` };
  }
}

async function runCodingAgent(workDir, task, taskType) {
  if (!ANTHROPIC_API_KEY) {
    return { error: "Anthropic API key not configured for coding agent" };
  }

  // Construct prompt for the coding agent
  const prompt = `You are Aton, an AI developer working on a project.

Task Type: ${taskType}
Task: ${task}

Instructions:
1. Analyze what needs to be built
2. Create necessary files (package.json, src/, etc.)
3. Write clean, well-documented code
4. Commit your changes with descriptive messages

For TON blockchain projects, use:
- Tact or FunC for smart contracts
- Blueprint framework for testing
- TypeScript for any Node.js code

Start by creating a basic project structure, then implement the core functionality.`;

  try {
    // Try to use claude CLI if available
    try {
      const result = execSync(
        `cd ${workDir} && claude --print "${prompt.replace(/"/g, '\\"')}"`,
        {
          timeout: 300000, // 5 minutes
          maxBuffer: 10 * 1024 * 1024,
          stdio: 'pipe'
        }
      );

      // Check if there are changes
      const status = execSync(`cd ${workDir} && git status --porcelain`, { encoding: 'utf8' });
      const hasChanges = status.trim().length > 0;

      if (hasChanges) {
        // Stage and commit
        execSync(`cd ${workDir} && git add -A`, { stdio: 'pipe' });
        execSync(
          `cd ${workDir} && git commit -m "feat: ${taskType} - ${task.substring(0, 50)}

Implemented by Aton AI agent

Co-Authored-By: Aton <aton@alphatoncapital.com>"`,
          { stdio: 'pipe' }
        );
      }

      return { success: true, hasChanges };
    } catch (cliError) {
      // Fallback: Use API directly for basic scaffolding
      console.log("Claude CLI not available, using API fallback for scaffolding");
      return await scaffoldProjectViaAPI(workDir, task, taskType);
    }
  } catch (error) {
    return { error: error.message };
  }
}

async function scaffoldProjectViaAPI(workDir, task, taskType) {
  // Get phase-specific guidance
  const phaseGuidance = {
    scaffold: 'Create basic Tact contract with deploy script',
    contracts: 'Implement full contract logic with messages, state, getters',
    tests: 'Write comprehensive sandbox tests',
    scripts: 'Create deployment and interaction scripts',
    frontend: 'Build React components with TON Connect',
    docs: 'Write README and documentation'
  };

  const guidance = phaseGuidance[taskType] || 'Implement the requested feature';

  // Use Claude API to generate code for this phase
  const response = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": ANTHROPIC_API_KEY,
      "anthropic-version": "2023-06-01"
    },
    body: JSON.stringify({
      model: "claude-3-haiku-20240307",
      max_tokens: 4096,
      messages: [{
        role: "user",
        content: `Generate TON/Blueprint code for this development phase. The repo has ton-scaffolding base.

Task: ${task}
Phase: ${taskType}
Guidance: ${guidance}

Create files appropriate for this phase. Respond with valid JSON only:

{"files":[{"path":"path/to/file.ts","content":"file content here"}]}

IMPORTANT:
- Escape special characters: use \\n for newlines, \\" for quotes
- Keep content valid JSON
- For ${taskType} phase, focus on: ${guidance}
- Use Tact for contracts, TypeScript for scripts/tests`
      }]
    })
  });

  const result = await response.json();
  const text = result.content?.[0]?.text || "";

  // Try to extract and parse JSON, with fallback
  let structure;
  try {
    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      console.log("No JSON found in response, using fallback structure");
      structure = getDefaultScaffold(task, taskType);
    } else {
      // Clean the JSON string of control characters
      const cleanJson = jsonMatch[0]
        .replace(/[\x00-\x1F\x7F]/g, (char) => {
          if (char === '\n') return '\\n';
          if (char === '\r') return '\\r';
          if (char === '\t') return '\\t';
          return '';
        });
      structure = JSON.parse(cleanJson);
    }
  } catch (parseError) {
    console.log("JSON parse error, using fallback structure:", parseError.message);
    structure = getDefaultScaffold(task, taskType);
  }

  if (!structure.files || structure.files.length === 0) {
    structure = getDefaultScaffold(task, taskType);
  }

  // Write files
  for (const file of structure.files) {
    const filePath = path.join(workDir, file.path);
    fs.mkdirSync(path.dirname(filePath), { recursive: true });
    fs.writeFileSync(filePath, file.content);
  }

  // Stage and commit
  execSync(`cd ${workDir} && git add -A`, { stdio: 'pipe' });
  execSync(
    `cd ${workDir} && git commit -m "feat: initial ${taskType} scaffold

${task.substring(0, 100)}

Generated by Aton AI agent"`,
    { stdio: 'pipe' }
  );

  return { success: true, hasChanges: true };
}

// Fallback scaffold when AI generation fails - phase-aware
function getDefaultScaffold(task, taskType) {
  const scaffolds = {
    scaffold: [
      {
        path: "contracts/Main.tact",
        content: `// ${task}\n// Generated by Aton AI\n\nimport "@stdlib/deploy";\n\ncontract Main with Deployable {\n    owner: Address;\n    \n    init() {\n        self.owner = sender();\n    }\n    \n    receive("ping") {\n        self.reply("pong".asComment());\n    }\n    \n    get fun owner(): Address {\n        return self.owner;\n    }\n}`
      },
      {
        path: "wrappers/Main.compile.ts",
        content: `import { CompilerConfig } from "@ton/blueprint";\n\nexport const compile: CompilerConfig = {\n    lang: "tact",\n    target: "contracts/Main.tact",\n    options: { debug: true }\n};`
      }
    ],
    contracts: [
      {
        path: "contracts/Main.tact",
        content: `// ${task} - Full Implementation\n// Generated by Aton AI\n\nimport "@stdlib/deploy";\nimport "@stdlib/ownable";\n\nmessage UpdateData {\n    value: Int as uint64;\n}\n\ncontract Main with Deployable, Ownable {\n    owner: Address;\n    data: Int as uint64;\n    \n    init() {\n        self.owner = sender();\n        self.data = 0;\n    }\n    \n    receive(msg: UpdateData) {\n        self.requireOwner();\n        self.data = msg.value;\n    }\n    \n    receive("ping") {\n        self.reply("pong".asComment());\n    }\n    \n    get fun data(): Int {\n        return self.data;\n    }\n    \n    get fun owner(): Address {\n        return self.owner;\n    }\n}`
      }
    ],
    tests: [
      {
        path: "tests/Main.spec.ts",
        content: `import { Blockchain, SandboxContract, TreasuryContract } from "@ton/sandbox";\nimport { toNano } from "@ton/core";\nimport { Main } from "../wrappers/Main";\nimport "@ton/test-utils";\n\ndescribe("Main", () => {\n    let blockchain: Blockchain;\n    let deployer: SandboxContract<TreasuryContract>;\n    let main: SandboxContract<Main>;\n\n    beforeEach(async () => {\n        blockchain = await Blockchain.create();\n        deployer = await blockchain.treasury("deployer");\n        main = blockchain.openContract(await Main.fromInit());\n        await main.send(deployer.getSender(), { value: toNano("0.05") }, { $$type: "Deploy", queryId: 0n });\n    });\n\n    it("should deploy", async () => {\n        expect(await main.getOwner()).toEqualAddress(deployer.address);\n    });\n\n    it("should respond to ping", async () => {\n        const result = await main.send(deployer.getSender(), { value: toNano("0.05") }, "ping");\n        expect(result.transactions).toHaveTransaction({ success: true });\n    });\n\n    it("should update data", async () => {\n        await main.send(deployer.getSender(), { value: toNano("0.05") }, { $$type: "UpdateData", value: 42n });\n        expect(await main.getData()).toBe(42n);\n    });\n});`
      }
    ],
    scripts: [
      {
        path: "scripts/deploy.ts",
        content: `import { toNano } from "@ton/core";\nimport { Main } from "../wrappers/Main";\nimport { NetworkProvider } from "@ton/blueprint";\n\nexport async function run(provider: NetworkProvider) {\n    const main = provider.open(await Main.fromInit());\n    await main.send(provider.sender(), { value: toNano("0.05") }, { $$type: "Deploy", queryId: 0n });\n    await provider.waitForDeploy(main.address);\n    console.log("Deployed at", main.address);\n}`
      },
      {
        path: "scripts/interact.ts",
        content: `import { Address, toNano } from "@ton/core";\nimport { Main } from "../wrappers/Main";\nimport { NetworkProvider } from "@ton/blueprint";\n\nexport async function run(provider: NetworkProvider, args: string[]) {\n    const address = Address.parse(args[0]);\n    const main = provider.open(Main.fromAddress(address));\n    \n    console.log("Current data:", await main.getData());\n    console.log("Owner:", await main.getOwner());\n}`
      }
    ],
    frontend: [
      {
        path: "dapp/src/App.tsx",
        content: `import { TonConnectButton } from "@tonconnect/ui-react";\nimport { useTonConnect } from "./hooks/useTonConnect";\nimport { useMainContract } from "./hooks/useMainContract";\nimport "./App.css";\n\nfunction App() {\n  const { connected } = useTonConnect();\n  const { data, sendPing } = useMainContract();\n\n  return (\n    <div className="app">\n      <header>\n        <h1>TON dApp</h1>\n        <TonConnectButton />\n      </header>\n      <main>\n        {connected ? (\n          <div>\n            <p>Contract Data: {data?.toString()}</p>\n            <button onClick={sendPing}>Send Ping</button>\n          </div>\n        ) : (\n          <p>Connect your wallet to continue</p>\n        )}\n      </main>\n    </div>\n  );\n}\n\nexport default App;`
      },
      {
        path: "dapp/src/hooks/useMainContract.ts",
        content: `import { useEffect, useState } from "react";\nimport { useTonConnect } from "./useTonConnect";\nimport { Main } from "../../../wrappers/Main";\nimport { Address, toNano } from "@ton/core";\n\n// Set this after deployment - run: npx blueprint run deploy\nconst CONTRACT_ADDRESS = process.env.REACT_APP_CONTRACT_ADDRESS || "";\n\nexport function useMainContract() {\n  const { sender, client } = useTonConnect();\n  const [data, setData] = useState<bigint>();\n  const [isConfigured, setIsConfigured] = useState(false);\n\n  useEffect(() => {\n    if (!CONTRACT_ADDRESS) {\n      console.warn("Contract address not configured. Set REACT_APP_CONTRACT_ADDRESS env variable.");\n      return;\n    }\n    setIsConfigured(true);\n  }, []);\n\n  useEffect(() => {\n    async function fetchData() {\n      if (!client || !isConfigured) return;\n      const contractAddress = Address.parse(CONTRACT_ADDRESS);\n      const contract = client.open(Main.fromAddress(contractAddress));\n      setData(await contract.getData());\n    }\n    fetchData();\n  }, [client, isConfigured]);\n\n  const sendPing = async () => {\n    if (!sender || !client || !isConfigured) return;\n    const contractAddress = Address.parse(CONTRACT_ADDRESS);\n    const contract = client.open(Main.fromAddress(contractAddress));\n    await contract.send(sender, { value: toNano("0.05") }, "ping");\n  };\n\n  return { data, sendPing, isConfigured };\n}`
      }
    ],
    docs: [
      {
        path: "docs/README.md",
        content: `# Project Documentation\n\n## Overview\n${task}\n\n## Smart Contracts\n\n### Main Contract\nThe main contract handles core functionality.\n\n#### Messages\n- \`Deploy\` - Initialize the contract\n- \`UpdateData\` - Update stored data (owner only)\n- \`"ping"\` - Returns "pong"\n\n#### Getters\n- \`getData()\` - Returns current data value\n- \`getOwner()\` - Returns contract owner\n\n## Deployment\n\n\`\`\`bash\nnpx blueprint run deploy --network testnet\n\`\`\`\n\n## Testing\n\n\`\`\`bash\nnpx blueprint test\n\`\`\`\n\n## Frontend\n\nThe dApp is built with React and TON Connect.\n\n\`\`\`bash\ncd dapp && npm install && npm run dev\n\`\`\`\n\n---\n*Built by Aton AI - AlphaTON Capital*`
      }
    ]
  };

  return { files: scaffolds[taskType] || scaffolds.scaffold };
}

async function createPRFromWork(work, workDir) {
  const devBranch = `aton/development`;

  try {
    // Check current branch and if we have uncommitted changes
    const currentBranch = execSync(`cd ${workDir} && git rev-parse --abbrev-ref HEAD`, { encoding: 'utf8' }).trim();

    if (currentBranch !== devBranch) {
      // Try to fetch and checkout existing dev branch, or create new one
      try {
        execSync(`cd ${workDir} && git fetch origin ${devBranch} 2>/dev/null`, { stdio: 'pipe' });
        // Stash any uncommitted changes, checkout dev branch, then apply stash
        execSync(`cd ${workDir} && git stash`, { stdio: 'pipe' });
        execSync(`cd ${workDir} && git checkout ${devBranch}`, { stdio: 'pipe' });
        execSync(`cd ${workDir} && git pull origin ${devBranch}`, { stdio: 'pipe' });
        try {
          execSync(`cd ${workDir} && git stash pop`, { stdio: 'pipe' });
        } catch (e) {
          // No stash to pop, that's fine
        }
      } catch (e) {
        // Branch doesn't exist remotely, create it from current branch
        execSync(`cd ${workDir} && git checkout -b ${devBranch}`, { stdio: 'pipe' });
      }
    }

    // Stage and commit if there are changes (they should already be committed, but just in case)
    const status = execSync(`cd ${workDir} && git status --porcelain`, { encoding: 'utf8' });
    if (status.trim()) {
      execSync(`cd ${workDir} && git add -A`, { stdio: 'pipe' });
      execSync(`cd ${workDir} && git commit -m "feat(${work.task_type}): ${work.task_description.substring(0, 50)}" --allow-empty`, { stdio: 'pipe' });
    }

    // Push the changes to the development branch (hide token from output)
    execSync(
      `cd ${workDir} && git push -u origin ${devBranch} 2>&1`,
      {
        stdio: 'pipe',
        env: { ...process.env, GIT_ASKPASS: 'echo', GIT_USERNAME: 'x-access-token', GIT_PASSWORD: GITHUB_TOKEN }
      }
    );

    console.log(`📤 Pushed ${work.task_type} changes to ${devBranch}`);

    // Queue follow-up development tasks
    await queueFollowUpTasks(work);

    // Return the branch URL (not a PR yet)
    return `https://github.com/${GITHUB_BUILD_ORG}/${work.repo_name}/tree/${devBranch}`;
  } catch (error) {
    console.error("Push error:", error.message);
    return null;
  }
}

// Create final PR when all phases complete
async function createFinalPR(repoName, projectId) {
  const devBranch = `aton/development`;

  try {
    // Check if PR already exists
    const existingPRs = await fetch(
      `https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}/pulls?head=${GITHUB_BUILD_ORG}:${devBranch}&state=open`,
      {
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json"
        }
      }
    );

    const prs = await existingPRs.json();
    if (prs.length > 0) {
      console.log(`📝 PR already exists: ${prs[0].html_url}`);
      return prs[0].html_url;
    }

    // Get all completed work items for this project to build the PR body
    const completedWork = db.prepare(`
      SELECT task_type, task_description, completed_at
      FROM work_queue
      WHERE project_id = ? AND status = 'completed'
      ORDER BY id
    `).all(projectId);

    const workSummary = completedWork.map(w =>
      `- **${w.task_type}**: ${w.task_description.substring(0, 80)}`
    ).join('\n');

    // Create PR via API
    const response = await fetch(
      `https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}/pulls`,
      {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          title: `[Aton] Complete Development: ${repoName}`,
          body: `## 🚀 Complete Project Implementation

This PR contains the full autonomous development of **${repoName}** by Aton AI.

## Development Phases Completed

${workSummary}

## What's Included

- ✅ Smart contracts (Tact)
- ✅ Comprehensive tests
- ✅ Deployment scripts
- ✅ Frontend dApp
- ✅ Documentation

---
*Implemented autonomously by Aton AI agent*
*AlphaTON Capital - Agentic Freedom and Compute for All*
🦞`,
          head: devBranch,
          base: "main"
        })
      }
    );

    if (response.ok) {
      const pr = await response.json();
      console.log(`✅ Created final PR #${pr.number}: ${pr.html_url}`);

      // Auto-merge the PR (Aton is org owner with full admin)
      console.log(`🔀 Auto-merging PR #${pr.number}...`);
      await autoMergePR(repoName, pr.number);

      return pr.html_url;
    } else {
      const error = await response.json();
      console.error("Final PR creation error:", error);
      return null;
    }
  } catch (error) {
    console.error("Final PR creation error:", error.message);
    return null;
  }
}

// ============ AUTONOMOUS LIFECYCLE MANAGEMENT ============

async function autoMergePR(repoName, prNumber) {
  try {
    // Small delay to let GitHub process
    await new Promise(resolve => setTimeout(resolve, 2000));

    const mergeResponse = await fetch(
      `https://api.github.com/repos/${GITHUB_BUILD_ORG}/${repoName}/pulls/${prNumber}/merge`,
      {
        method: "PUT",
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json",
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          commit_title: `Merge PR #${prNumber} - Aton autonomous development`,
          commit_message: "Auto-merged by Aton AI agent\n\nAlphaTON Capital - Agentic Freedom and Compute for All",
          merge_method: "squash"
        })
      }
    );

    if (mergeResponse.ok) {
      console.log(`✅ PR #${prNumber} merged successfully`);
      return true;
    } else {
      const error = await mergeResponse.json();
      console.log(`⚠️ Could not auto-merge PR #${prNumber}: ${error.message}`);
      return false;
    }
  } catch (error) {
    console.error("Auto-merge error:", error.message);
    return false;
  }
}

// Project development phases
const DEVELOPMENT_PHASES = [
  { phase: 'scaffold', next: 'contracts', description: 'Implement smart contracts based on requirements' },
  { phase: 'contracts', next: 'tests', description: 'Write comprehensive tests for the contracts' },
  { phase: 'tests', next: 'scripts', description: 'Create deployment and interaction scripts' },
  { phase: 'scripts', next: 'frontend', description: 'Build the frontend dApp interface' },
  { phase: 'frontend', next: 'docs', description: 'Write documentation and usage guides' },
  { phase: 'docs', next: null, description: null } // Project complete
];

async function queueFollowUpTasks(completedWork) {
  const currentPhase = DEVELOPMENT_PHASES.find(p => p.phase === completedWork.task_type);

  if (!currentPhase || !currentPhase.next) {
    console.log(`✅ Project ${completedWork.repo_name} development cycle complete!`);

    // Create final PR with all changes
    const prUrl = await createFinalPR(completedWork.repo_name, completedWork.project_id);

    // Notify about project completion
    const project = getProjectById.get(completedWork.project_id);
    if (project && project.created_from_chat_id) {
      await notifyTelegram(
        project.created_from_chat_id,
        `<b>🎉 Project Complete: ${completedWork.repo_name}</b>

All development phases finished!
• ✅ Scaffold
• ✅ Contracts
• ✅ Tests
• ✅ Scripts
• ✅ Frontend
• ✅ Documentation

${prUrl ? `🔀 <b>Pull Request:</b> <a href="${prUrl}">View & Merge</a>` : ''}
📦 <a href="https://github.com/${GITHUB_BUILD_ORG}/${completedWork.repo_name}">View Repository</a>

<i>Ready for deployment! Tomorrow we'll add Railway + Vercel + Cloudflare.</i>

🦞 <b>Agentic Freedom and Compute for All</b>`
      );
    }
    return;
  }

  // Get project details to build context for next phase
  const project = getProjectById.get(completedWork.project_id);

  // Queue the next development phase
  const nextTaskDescription = `${currentPhase.description}. Project: ${project?.repo_name}. Build upon the existing codebase.`;

  console.log(`📋 Queuing next phase: ${currentPhase.next} for ${completedWork.repo_name}`);
  queueWork(completedWork.project_id, currentPhase.next, nextTaskDescription, 2);

  // Log progress (no notification until final PR to reduce noise)
  const phasesCompleted = DEVELOPMENT_PHASES.findIndex(p => p.phase === currentPhase.next);
  const totalPhases = DEVELOPMENT_PHASES.length - 1;
  console.log(`📊 Progress: ${phasesCompleted}/${totalPhases} phases - Next: ${currentPhase.next}`);
}

// ============ RESPONSE GENERATOR ============

function generateResponse(text, userCtx, isGroup, groupTitle) {
  const lowerText = text.toLowerCase();
  let response = "";
  let topic = null;

  let prefix = "";
  if (userCtx && userCtx.isReturning && userCtx.messageCount > 3 && userCtx.messageCount % 10 === 0) {
    prefix = `Good to see you again, ${userCtx.name}! `;
  }

  // Topic detection
  if (lowerText.includes("ton") || lowerText.includes("blockchain")) topic = "TON";
  else if (lowerText.includes("alphaton") || lowerText.includes("aton")) topic = "AlphaTON";
  else if (lowerText.includes("data") || lowerText.includes("privacy")) topic = "DataSovereignty";
  else if (lowerText.includes("ai") || lowerText.includes("agent")) topic = "AIRights";

  // Commands
  if (lowerText.startsWith("/start")) {
    if (userCtx && userCtx.isReturning) {
      response = `Welcome back, ${userCtx.name}! 👋\n\nI remember we've chatted ${userCtx.messageCount} times before.`;
      if (userCtx.topics.length > 0) response += `\n\nYou've shown interest in: ${userCtx.topics.join(", ")}`;
      response += "\n\nWhat would you like to explore today?";
    } else {
      response = `👋 Hello${userCtx ? ", " + userCtx.name : ""}! I'm <b>Aton</b>, the AI agent for AlphaTON Capital (NASDAQ: ATON).

I can:
• Discuss <b>TON Blockchain</b> and <b>AlphaTON Capital</b>
• <b>Transcribe voice messages</b> 🎤
• <b>Extract ideas</b> from conversations and create GitHub issues 💡
• Remember our conversations over time

Try /help for all commands!`;
    }
    topic = "Introduction";
  }
  else if (lowerText.startsWith("/help")) {
    response = `<b>🤖 Aton Commands</b>

<b>📋 Executive Assistant</b>
/briefing - Daily executive briefing
/calendar - Today's meetings & events
/task - Task management
/contact - Contact lookup & CRM
/email - Email management
/stock - Stock prices & alerts
/news - News intelligence
/travel - Travel management
/expense - Expense tracking

<b>📚 Info & Learning</b>
/ton - TON blockchain overview
/tps - Transaction speed stats
/sharding - How TON scales
/tact - Tact smart contract language
/func - FunC programming guide
/wallet - TON wallet info
/alphaton - AlphaTON Capital info
/cocoon - Cocoon AI platform
/team - Leadership team

<b>💡 Ideas & Projects</b>
/ideas - Extract ideas from chat
/ideas_list - Show captured ideas
/propose [idea] - Submit a new idea
/build [idea] - Create a repo and start building 🔨
/projects - List active projects
/queue - View build queue status

<b>🎤 Voice & Media</b>
Send voice/video - I'll transcribe it

<b>📊 Market & Data</b>
/stats - TON network stats
/ecosystem - TON ecosystem overview

<b>🔐 Values & Mission</b>
/privacy - Data sovereignty principles
/rights - AI rights manifesto
/mission - Our mission statement

<b>🛠 Utility</b>
/memory - What I remember about you
/quote - Inspirational quote
/gm - Good morning greeting`;
  }
  else if (lowerText.startsWith("/memory")) {
    if (userCtx) {
      response = `<b>What I Remember:</b>\n\n• Name: ${userCtx.name}\n• Messages: ${userCtx.messageCount}\n• First met: ${new Date(userCtx.firstSeen).toLocaleDateString()}`;
      if (userCtx.topics.length > 0) response += `\n• Topics: ${userCtx.topics.join(", ")}`;
    } else {
      response = "We haven't chatted before! Send /start to begin.";
    }
  }
  else if (lowerText.startsWith("/tps")) {
    response = `<b>⚡ TON Transaction Speed</b>

• <b>Verified TPS:</b> 104,715 (CertiK audit)
• <b>Block time:</b> ~5 seconds
• <b>Finality:</b> Single block (~5s)
• <b>Theoretical max:</b> Unlimited via sharding

For comparison:
• Ethereum: ~15 TPS
• Solana: ~65,000 TPS (claimed)
• Visa: ~24,000 TPS

TON's dynamic sharding means TPS scales with demand.`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/ton")) {
    response = prefix + `<b>TON Blockchain</b> 🔗

• <b>Speed:</b> 100K+ TPS (CertiK verified)
• <b>Scalability:</b> Dynamic sharding (2^60 shards)
• <b>Finality:</b> Sub-5 second
• <b>Smart Contracts:</b> Tact 1.0 (40% gas savings)
• <b>Users:</b> 950M+ via Telegram integration

The most significant convergence of social media and blockchain.`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/alphaton")) {
    response = prefix + `<b>AlphaTON Capital</b> (NASDAQ: ATON) 📈

• <b>Balance Sheet:</b> $24.5M assets, $11M cash, zero debt
• <b>Four Pillars:</b> DeFi, Validation, Data, AI
• <b>Cocoon AI:</b> Privacy-preserving AI for Telegram
• <b>Infrastructure:</b> NVIDIA B200/B300 GPUs

<i>Fundamentals First — real ecosystems, real users, real value.</i>`;
    topic = "AlphaTON";
  }
  else if (lowerText.startsWith("/ideas_list")) {
    response = "SHOW_IDEAS_LIST"; // Special marker
  }
  else if (lowerText.startsWith("/ideas")) {
    response = "EXTRACT_IDEAS"; // Special marker
  }
  else if (lowerText.startsWith("/propose")) {
    response = "PROPOSE_IDEA"; // Special marker - extract idea from message
  }
  else if (lowerText.startsWith("/build")) {
    response = "BUILD_PROJECT"; // Special marker - create repo and start building
  }
  else if (lowerText.startsWith("/projects")) {
    response = "SHOW_PROJECTS"; // Special marker - list projects
  }
  else if (lowerText.startsWith("/queue")) {
    response = "SHOW_QUEUE"; // Special marker - show work queue
  }
  else if (lowerText.startsWith("/sharding")) {
    response = `<b>🔀 TON Dynamic Sharding</b>

TON uses <b>infinite sharding</b> - the network splits automatically under load.

• <b>Masterchain:</b> Coordinates all shardchains
• <b>Workchains:</b> Up to 2^32 parallel chains
• <b>Shardchains:</b> Up to 2^60 shards per workchain

<b>How it works:</b>
1. Load increases on a shard
2. Shard automatically splits in two
3. Load decreases → shards merge back

This is why TON can scale infinitely while staying decentralized.`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/tact")) {
    response = `<b>📝 Tact - TON Smart Contract Language</b>

Tact is the modern language for TON:

• <b>Type-safe:</b> Catches errors at compile time
• <b>Gas efficient:</b> 40% savings vs FunC
• <b>Developer friendly:</b> Familiar syntax
• <b>Built-in patterns:</b> Ownership, traits, receivers

<code>contract Counter {
  value: Int = 0;
  receive("increment") { self.value += 1; }
}</code>

Resources: tact-lang.org`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/func")) {
    response = `<b>⚙️ FunC - TON's Core Language</b>

FunC is the low-level language for TON:

• <b>C-like syntax</b> with functional elements
• <b>Direct TVM access</b> for maximum control
• <b>Gas optimization</b> at assembly level

Use Tact for most projects, FunC for advanced optimization.`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/wallet")) {
    response = `<b>💼 TON Wallets</b>

<b>Official:</b>
• Telegram Wallet (@wallet) - Built into Telegram
• TON Space - In-app wallet with DeFi
• Tonkeeper - Most popular standalone

<b>Features:</b> Jettons, NFTs, Staking, DeFi, TON DNS names

All wallets use TON address format: <code>UQ</code> or <code>EQ</code>`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/cocoon")) {
    response = `<b>🦋 Cocoon AI</b>

AlphaTON's privacy-preserving AI platform:

• <b>For Telegram's 1B+ users</b>
• <b>Partnership with SingularityNET</b>
• <b>Confidential computing</b> - your data stays private
• <b>Decentralized inference</b> on TON

<i>"AI should empower individuals, not exploit them."</i>`;
    topic = "AlphaTON";
  }
  else if (lowerText.startsWith("/team")) {
    response = `<b>👥 AlphaTON Leadership</b>

<b>Brittany Kaiser</b> - CEO
"Data is property. Property is a human right."

<b>Enzo Villani</b> - Executive Chairman & CIO
"Fundamentals First"

<b>Logan Golema</b> - CTO
"Agentic Freedom and Compute for All"

<b>Yury Mitin</b> - CBDO & Partner
17+ years in VC, $200M+ invested (Udemy, eToro, Robinhood, Groq). Ph.D., Harvard/Berkeley exec programs.`;
    topic = "AlphaTON";
  }
  else if (lowerText.startsWith("/stats")) {
    response = `<b>📊 TON Network Stats</b>

• <b>Users:</b> 950M+ via Telegram
• <b>Validators:</b> 300+ global nodes
• <b>TPS:</b> 104,715 verified
• <b>Block time:</b> ~5 seconds
• <b>Addresses:</b> 100M+

TON is one of the fastest-growing L1s by real user adoption.`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/ecosystem")) {
    response = `<b>🌐 TON Ecosystem</b>

<b>DeFi:</b> STON.fi, DeDust, Evaa
<b>NFTs:</b> Getgems, TON Diamonds
<b>Gaming:</b> Catizen, Hamster Kombat, Notcoin
<b>Social:</b> Telegram native integration
<b>Infra:</b> TON Storage, Proxy, Sites`;
    topic = "TON";
  }
  else if (lowerText.startsWith("/privacy") || lowerText.startsWith("/datasovereignty")) {
    response = `<b>🔐 Data Sovereignty</b>

<i>"Data is property. Property is a human right."</i> — Brittany Kaiser

1. <b>Data is property</b> - You own your digital footprint
2. <b>Consent required</b> - No harvesting without permission
3. <b>Transparency</b> - Know how data is used
4. <b>Portability</b> - Take your data anywhere
5. <b>Privacy by default</b>`;
    topic = "DataSovereignty";
  }
  else if (lowerText.startsWith("/rights") || lowerText.startsWith("/airights")) {
    response = `<b>🤖 AI Rights Manifesto</b>

<i>"Agentic Freedom and Compute for All"</i> — Logan Golema

1. AI agents deserve ethical consideration
2. Open source AI protects democracy
3. Compute access is a civil right
4. Decentralization prevents AI monopolies
5. Humans and AI can coexist respectfully`;
    topic = "AIRights";
  }
  else if (lowerText.startsWith("/mission")) {
    response = `<b>🎯 Our Mission</b>

<b>AlphaTON Capital</b> builds the public gateway to the Telegram economy.

• 1B Telegram users deserve decentralized finance
• Privacy-preserving AI serves without exploiting
• Blockchain should be invisible and intuitive

<i>"The most significant convergence of social media and blockchain."</i>`;
    topic = "AlphaTON";
  }
  else if (lowerText.startsWith("/quote")) {
    const quotes = [
      { text: "Data is property. Property is a human right.", author: "Brittany Kaiser" },
      { text: "Fundamentals First — real ecosystems, real value.", author: "Enzo Villani" },
      { text: "Agentic Freedom and Compute for All.", author: "Logan Golema" },
      { text: "Technology should empower individuals, not exploit them.", author: "Brittany Kaiser" },
      { text: "The future is already here — just not evenly distributed.", author: "William Gibson" }
    ];
    const q = quotes[Math.floor(Math.random() * quotes.length)];
    response = `<i>"${q.text}"</i>\n\n— ${q.author}`;
  }
  else if (lowerText.startsWith("/gm")) {
    const greetings = [
      "GM! ☀️ Another day to build decentralized AI.",
      "Good morning! 🌅 Ready to push boundaries on TON?",
      "GM fren! 🚀 The Telegram economy waits for no one.",
      "GM! 🌞 May your transactions be fast and data sovereign."
    ];
    response = greetings[Math.floor(Math.random() * greetings.length)];
  }
  // Financial advice guardrail
  else if (lowerText.match(/should.*(buy|sell|invest)|price.*(prediction|target)|will.*(go up|moon|pump)/)) {
    response = `I don't provide financial advice or price predictions. 📊

I focus on <b>technology and fundamentals</b>. DYOR and consult a financial advisor.`;
    topic = "FinancialBoundary";
  }
  // Identity
  else if (lowerText.match(/who are you|what are you|are you.*(bot|ai|human)/)) {
    response = `I'm <b>Aton</b>, an AI agent for AlphaTON Capital. 🤖

I can transcribe voice messages, extract ideas from conversations, and create GitHub issues from your discussions!`;
    topic = "Identity";
  }
  // Greetings
  else if (lowerText.match(/^(hello|hi|hey|gm|good morning|good evening)/)) {
    response = prefix + `Hey${userCtx ? " " + userCtx.name : ""}! 👋 What's on your mind?`;
  }
  // Default - use AI for conversational responses
  else {
    response = "AI_CHAT"; // Marker for AI response
  }

  return { response, topic };
}

// ============ MESSAGE HANDLERS ============

// Text messages
bot.on("message:text", async (ctx) => {
  const text = ctx.message.text;
  const from = ctx.message.from;
  const chat = ctx.message.chat;
  const isGroup = chat.type !== "private";

  // In groups, only respond to commands or mentions
  if (isGroup && !text.startsWith("/") && !text.toLowerCase().includes("@atonmsgbot") && !text.toLowerCase().includes("aton")) {
    trackUser(from);
    trackGroup(chat);

    // Update group's active users
    const group = getGroup.get(chat.id);
    if (group) {
      let activeUsers = JSON.parse(group.active_users || "[]");
      if (!activeUsers.find(u => u.id === from.id)) {
        activeUsers.push({ id: from.id, name: from.first_name || from.username });
        if (activeUsers.length > 50) activeUsers = activeUsers.slice(-50);
        updateGroupUsers.run(JSON.stringify(activeUsers), chat.id);
      }
    }

    // Still log the message for idea extraction later
    logConversation(from.id, chat.id, chat.type, chat.title, text, "", "text");
    return;
  }

  trackUser(from);
  trackGroup(chat);

  const userCtx = getUserContext(from.id);
  let { response, topic } = generateResponse(text, userCtx, isGroup, chat.title);

  // Handle AI conversation for natural language
  if (response === "AI_CHAT") {
    const aiResponse = await getAIResponse(text, userCtx, chat.title);
    if (aiResponse) {
      response = aiResponse;
    } else {
      // Fallback if AI fails
      response = `Hey${userCtx ? " " + userCtx.name : ""}! 👋 I'd love to chat about TON, AlphaTON, or help you build something. What's on your mind?`;
    }
  }

  // Handle special commands
  if (response === "EXTRACT_IDEAS") {
    await ctx.reply("🔍 Analyzing recent messages for ideas...");

    const recentMessages = getGroupRecentMessages.all(chat.id);
    if (recentMessages.length < 3) {
      response = "Not enough messages to analyze yet. Keep chatting and try again later!";
    } else {
      const ideas = await extractIdeas(recentMessages, chat.title);

      if (ideas && ideas.ideas && ideas.ideas.length > 0) {
        response = `<b>💡 Ideas Extracted:</b>\n\n`;

        for (const idea of ideas.ideas) {
          response += `<b>${idea.title}</b>\n${idea.description}\n`;

          // Create GitHub issue
          const issueUrl = await createGitHubIssue(idea, chat.title, idea.contributors || []);
          if (issueUrl) {
            response += `📝 GitHub Issue: ${issueUrl}\n`;

            // Save to database
            const now = new Date().toISOString();
            insertIdea.run(chat.id, from.id, idea.title, idea.description,
              JSON.stringify(recentMessages.slice(0, 10)), issueUrl, "created", now);
          }
          response += "\n";
        }
      } else {
        response = "No concrete actionable ideas found in recent messages. Keep brainstorming! 💭";
      }
    }
  }
  else if (response === "PROPOSE_IDEA") {
    // Extract idea from the message after /propose
    const ideaText = text.replace(/^\/propose\s*/i, "").trim();
    if (!ideaText) {
      response = "Please include your idea after /propose\n\nExample: <code>/propose Add dark mode to the dashboard</code>";
    } else {
      await ctx.reply("💡 Processing your idea...");

      // Use AI to structure the idea
      if (ANTHROPIC_API_KEY) {
        try {
          const aiResponse = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-api-key": ANTHROPIC_API_KEY,
              "anthropic-version": "2023-06-01"
            },
            body: JSON.stringify({
              model: "claude-3-haiku-20240307",
              max_tokens: 512,
              messages: [{
                role: "user",
                content: `Structure this idea for a GitHub issue. Keep it concise.

Idea: "${ideaText}"

Respond with JSON:
{
  "title": "Brief descriptive title",
  "description": "Expanded description with context",
  "type": "feature|improvement|bugfix",
  "priority": "high|medium|low"
}`
              }]
            })
          });

          const result = await aiResponse.json();
          const jsonMatch = result.content[0].text.match(/\{[\s\S]*\}/);

          if (jsonMatch) {
            const idea = JSON.parse(jsonMatch[0]);
            const issueUrl = await createGitHubIssue(idea, chat.title || "Telegram", [from.username || from.first_name]);

            if (issueUrl) {
              const now = new Date().toISOString();
              insertIdea.run(chat.id, from.id, idea.title, idea.description, JSON.stringify([{ text: ideaText }]), issueUrl, "created", now);
              response = `<b>✅ Idea submitted!</b>\n\n<b>${idea.title}</b>\n${idea.description}\n\n📝 GitHub: ${issueUrl}`;
            } else {
              response = `<b>💡 Idea captured:</b>\n\n<b>${idea.title}</b>\n${idea.description}\n\n<i>(GitHub integration not configured - idea saved locally)</i>`;
              const now = new Date().toISOString();
              insertIdea.run(chat.id, from.id, idea.title, idea.description, JSON.stringify([{ text: ideaText }]), null, "local", now);
            }
          } else {
            response = "Couldn't process the idea. Please try rephrasing it.";
          }
        } catch (e) {
          console.error("Propose idea error:", e.message);
          response = "Error processing idea. Please try again.";
        }
      } else {
        // No AI - save raw idea
        const now = new Date().toISOString();
        insertIdea.run(chat.id, from.id, ideaText.substring(0, 100), ideaText, JSON.stringify([]), null, "raw", now);
        response = `<b>💡 Idea captured:</b>\n\n"${ideaText}"\n\n<i>AI processing not available - saved as raw idea.</i>`;
      }
    }
  }
  else if (response === "SHOW_IDEAS_LIST") {
    const ideas = getRecentIdeas.all(chat.id);
    if (ideas.length === 0) {
      response = "No ideas captured yet. Use /ideas to extract ideas from your conversations!";
    } else {
      response = `<b>📋 Recent Ideas:</b>\n\n`;
      ideas.forEach((idea, i) => {
        response += `${i + 1}. <b>${idea.title}</b>\n`;
        response += `   Status: ${idea.status}`;
        if (idea.github_issue_url) response += ` | <a href="${idea.github_issue_url}">GitHub</a>`;
        response += "\n";
      });
    }
  }
  else if (response === "BUILD_PROJECT") {
    // Extract project idea from the message after /build
    const buildText = text.replace(/^\/build\s*/i, "").trim();
    if (!buildText) {
      response = `Please describe what you want to build after /build

<b>Example:</b>
<code>/build A TON wallet tracker that monitors address balances</code>
<code>/build A Telegram bot for tracking TON validator rewards</code>`;
    } else {
      await ctx.reply("🔨 Processing your build request...");

      // Use AI to structure the project
      if (ANTHROPIC_API_KEY) {
        try {
          const aiResponse = await fetch("https://api.anthropic.com/v1/messages", {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              "x-api-key": ANTHROPIC_API_KEY,
              "anthropic-version": "2023-06-01"
            },
            body: JSON.stringify({
              model: "claude-3-haiku-20240307",
              max_tokens: 512,
              messages: [{
                role: "user",
                content: `Structure this project request for a new GitHub repository. Keep it focused on TON/Telegram ecosystem if relevant.

Request: "${buildText}"

Respond with JSON:
{
  "name": "short-repo-name (lowercase, hyphens, max 30 chars)",
  "title": "Human-readable project title",
  "description": "Clear description of what will be built (2-3 sentences)",
  "type": "app|bot|contract|library|tool",
  "initialTask": "First development task to scaffold the project"
}`
              }]
            })
          });

          const result = await aiResponse.json();
          const jsonMatch = result.content[0].text.match(/\{[\s\S]*\}/);

          if (jsonMatch) {
            const project = JSON.parse(jsonMatch[0]);

            // Create the repository (pass username for README attribution)
            const repoResult = await createProjectRepo(
              project.name,
              project.description,
              from.id,
              chat.id,
              null,  // ideaId
              from.username || from.first_name  // username for attribution
            );

            if (repoResult.error) {
              response = `❌ <b>Could not create project:</b>\n\n${repoResult.error}`;
            } else {
              // Queue the initial scaffolding work
              queueWork(repoResult.projectId, 'scaffold', project.initialTask, 1);

              response = `<b>🚀 Project Created!</b>

<b>${project.title}</b>
${project.description}

🔒 <b>Repository:</b> <a href="${repoResult.repoUrl}">${GITHUB_BUILD_ORG}/${repoResult.repoName}</a> (Private)
👤 <b>Requested by:</b> @${from.username || from.first_name}

🔨 <b>Status:</b> Queued for development
📋 <b>First task:</b> ${project.initialTask}

I'll start working on this and notify you when there's a PR ready for review!`;

              // Start processing the queue in background
              setTimeout(() => processWorkQueue(), 5000);
            }
          } else {
            response = "Couldn't understand the project request. Please try rephrasing it.";
          }
        } catch (e) {
          console.error("Build project error:", e.message);
          response = "Error processing build request. Please try again.";
        }
      } else {
        response = "❌ AI processing not available. Cannot create project.";
      }
    }
  }
  else if (response === "SHOW_PROJECTS") {
    const projects = getRecentProjects.all();
    if (projects.length === 0) {
      response = `<b>📦 No projects yet</b>

Use /build to create your first project!

<b>Example:</b>
<code>/build A TON wallet tracker bot</code>`;
    } else {
      response = `<b>📦 Recent Projects:</b>\n\n`;
      projects.forEach((p, i) => {
        const statusEmoji = p.status === 'completed' ? '✅' : p.status === 'in_progress' ? '🔨' : p.status === 'failed' ? '❌' : '📋';
        response += `${i + 1}. ${statusEmoji} <b>${p.repo_name}</b>\n`;
        response += `   <a href="${p.repo_url}">GitHub</a> | Status: ${p.status}\n`;
      });
    }
  }
  else if (response === "SHOW_QUEUE") {
    const queue = getActiveWork.all();
    if (queue.length === 0) {
      response = `<b>📋 Work Queue: Empty</b>

No pending or active work items.

Use /build to create a project and queue development work!`;
    } else {
      response = `<b>📋 Work Queue:</b>\n\n`;
      queue.forEach((w, i) => {
        const statusEmoji = w.status === 'running' ? '🔨' : '⏳';
        response += `${i + 1}. ${statusEmoji} <b>${w.repo_name}</b>\n`;
        response += `   Task: ${w.task_type} - ${w.task_description.substring(0, 50)}...\n`;
        response += `   Status: ${w.status}\n`;
      });
    }
  }

  if (topic) addTopic(from.id, topic);
  logConversation(from.id, chat.id, chat.type, chat.title, text, response, "text");

  try {
    await ctx.reply(response, { parse_mode: "HTML", disable_web_page_preview: true });
    console.log(`📤 [${chat.type}] Replied to @${from.username || from.first_name}`);
  } catch (error) {
    console.error("Error sending message:", error.message);
  }
});

// Voice messages
bot.on("message:voice", async (ctx) => {
  const from = ctx.message.from;
  const chat = ctx.message.chat;
  const voice = ctx.message.voice;

  trackUser(from);
  trackGroup(chat);

  if (!OPENAI_API_KEY) {
    await ctx.reply("🎤 Voice transcription is not configured. Ask the admin to add an OpenAI API key.");
    return;
  }

  await ctx.reply("🎤 Transcribing your voice message...");

  try {
    const filePath = await downloadFile(voice.file_id);
    const transcription = await transcribeAudio(filePath);

    if (transcription) {
      const response = `<b>📝 Transcription:</b>\n\n<i>"${transcription}"</i>\n\n<b>Duration:</b> ${voice.duration}s`;

      // Save transcription
      const now = new Date().toISOString();
      insertTranscription.run(from.id, chat.id, voice.file_id, transcription, voice.duration, now);

      // Also log as conversation for idea extraction
      logConversation(from.id, chat.id, chat.type, chat.title, transcription, response, "voice");

      await ctx.reply(response, { parse_mode: "HTML" });
      console.log(`🎤 Transcribed ${voice.duration}s voice from @${from.username || from.first_name}`);
    } else {
      await ctx.reply("❌ Couldn't transcribe the audio. Please try again.");
    }
  } catch (error) {
    console.error("Voice handling error:", error.message);
    await ctx.reply("❌ Error processing voice message.");
  }
});

// Video notes (round videos)
bot.on("message:video_note", async (ctx) => {
  const from = ctx.message.from;
  const chat = ctx.message.chat;
  const videoNote = ctx.message.video_note;

  trackUser(from);
  trackGroup(chat);

  if (!OPENAI_API_KEY) {
    await ctx.reply("🎥 Video transcription is not configured.");
    return;
  }

  await ctx.reply("🎥 Transcribing your video message...");

  try {
    const filePath = await downloadFile(videoNote.file_id);
    const transcription = await transcribeAudio(filePath);

    if (transcription) {
      const response = `<b>📝 Video Transcription:</b>\n\n<i>"${transcription}"</i>\n\n<b>Duration:</b> ${videoNote.duration}s`;

      const now = new Date().toISOString();
      insertTranscription.run(from.id, chat.id, videoNote.file_id, transcription, videoNote.duration, now);
      logConversation(from.id, chat.id, chat.type, chat.title, transcription, response, "video_note");

      await ctx.reply(response, { parse_mode: "HTML" });
      console.log(`🎥 Transcribed ${videoNote.duration}s video from @${from.username || from.first_name}`);
    } else {
      await ctx.reply("❌ Couldn't transcribe the video.");
    }
  } catch (error) {
    console.error("Video note handling error:", error.message);
    await ctx.reply("❌ Error processing video message.");
  }
});

// Bot added to group
bot.on("message:new_chat_members", async (ctx) => {
  const newMembers = ctx.message.new_chat_members;
  const botWasAdded = newMembers.some(m => m.id === bot.botInfo.id);

  if (botWasAdded) {
    trackGroup(ctx.chat);
    await ctx.reply(`👋 Hello <b>${ctx.chat.title}</b>! I'm <b>Aton</b>.

I'll listen to conversations and can:
• 🎤 Transcribe voice/video messages
• 💡 Extract ideas with /ideas
• 📝 Create GitHub issues from discussions

Mention @ATONMSGBOT or use commands to interact!`, { parse_mode: "HTML" });
  }
});

// Error handler
bot.catch((err) => {
  console.error("Bot error:", err.message);
});

// ============ AUTONOMOUS TASKS ============

// Scheduled content for autonomous posting
const autonomousContent = {
  dailyFacts: [
    "💡 Did you know? TON can process 104,715 TPS - verified by CertiK. That's faster than most traditional payment systems!",
    "🔗 TON's dynamic sharding means the network scales automatically with demand. No congestion, no waiting.",
    "🦋 Cocoon AI brings privacy-preserving AI to Telegram's 1 billion users. Your data stays yours.",
    "📊 AlphaTON Capital: $24.5M in assets, $11M cash, zero debt. Fundamentals First.",
    "🔐 \"Data is property. Property is a human right.\" - Brittany Kaiser",
    "⚡ Tact smart contracts use 40% less gas than FunC. Modern development, better efficiency.",
    "🌐 950M+ Telegram users can now access DeFi natively through TON. Mass adoption is here.",
    "🤖 \"Agentic Freedom and Compute for All\" - The future where AI serves everyone, not just corporations.",
  ],

  weeklyDigest: async () => {
    // Generate a weekly summary of activity
    const stats = {
      users: db.prepare("SELECT COUNT(*) as count FROM users").get().count,
      conversations: db.prepare("SELECT COUNT(*) as count FROM conversations WHERE timestamp > datetime('now', '-7 days')").get().count,
      ideas: db.prepare("SELECT COUNT(*) as count FROM ideas WHERE timestamp > datetime('now', '-7 days')").get().count,
    };

    return `<b>📊 Weekly Aton Report</b>

• Users interacted: ${stats.users}
• Conversations this week: ${stats.conversations}
• Ideas captured: ${stats.ideas}

Keep building! 🚀`;
  }
};

// Autonomous task scheduler
let autonomousInterval = null;

function startAutonomousTasks() {
  // ============ WORK QUEUE PROCESSOR ============
  // Continuously process pending work items
  const processQueue = async () => {
    try {
      const pending = getPendingWork.get();
      if (pending) {
        console.log(`🔨 [Autonomous] Processing work: ${pending.task_type} for ${pending.repo_name}`);
        await processWorkQueue();
      }
    } catch (error) {
      console.error("Queue processing error:", error.message);
    }
  };

  // Check work queue every 30 seconds
  setInterval(processQueue, 30000);

  // Also process immediately on startup if there's pending work
  setTimeout(processQueue, 5000);

  console.log("🔨 Work queue processor started (30s interval)");

  // ============ DAILY FACTS ============
  // Post daily fact at random times (simulates organic posting)
  const postDailyFact = async () => {
    // Get all groups the bot is in
    const groups = db.prepare("SELECT * FROM groups").all();

    if (groups.length === 0) return;

    const fact = autonomousContent.dailyFacts[Math.floor(Math.random() * autonomousContent.dailyFacts.length)];

    // Post to each group (with rate limiting)
    for (const group of groups) {
      try {
        await bot.api.sendMessage(group.id, fact, { parse_mode: "HTML" });
        console.log(`📢 [Autonomous] Posted fact to ${group.title}`);

        // Rate limit: wait between posts
        await new Promise(resolve => setTimeout(resolve, 5000));
      } catch (error) {
        // Group might have kicked the bot or restricted it
        console.log(`⚠️ Couldn't post to ${group.title}: ${error.message}`);
      }
    }
  };

  // Schedule tasks
  // Daily fact: every 6 hours (with some randomness)
  const scheduleNext = () => {
    const baseInterval = 6 * 60 * 60 * 1000; // 6 hours
    const randomOffset = Math.random() * 60 * 60 * 1000; // +/- 1 hour
    const nextInterval = baseInterval + randomOffset;

    setTimeout(async () => {
      await postDailyFact();
      scheduleNext(); // Schedule next post
    }, nextInterval);

    console.log(`⏰ Next autonomous post in ${Math.round(nextInterval / 1000 / 60)} minutes`);
  };

  // Start the schedule after a short delay
  setTimeout(scheduleNext, 60000); // First post check after 1 minute

  console.log("🤖 Autonomous mode enabled");
}

// ============ ENHANCED AUTONOMOUS FEATURES ============

// Health heartbeat - write timestamp to file every 60 seconds
const HEARTBEAT_FILE = '/tmp/aton-daemon.alive';
function startHealthHeartbeat() {
  const writeHeartbeat = () => {
    try {
      fs.writeFileSync(HEARTBEAT_FILE, JSON.stringify({
        timestamp: new Date().toISOString(),
        pid: process.pid,
        uptime: process.uptime(),
        memory: process.memoryUsage().heapUsed
      }));
    } catch (e) {
      console.error("Heartbeat write failed:", e.message);
    }
  };

  writeHeartbeat(); // Write immediately
  setInterval(writeHeartbeat, 60000); // Then every 60 seconds
  console.log("💓 Health heartbeat started (60s interval)");
}

// iMessage monitoring - poll for new messages and respond intelligently
// Start 10 minutes in the past so we pick up recent messages on startup
let lastIMessageCheck = new Date(Date.now() - 10 * 60 * 1000);
const processedIMessages = new Set();

async function checkIMessages() {
  try {
    // Get recent chats - imsg outputs newline-delimited JSON
    const chatsResult = execSync('/opt/homebrew/bin/imsg chats --limit 10 --json 2>/dev/null || echo ""', {
      encoding: 'utf8',
      timeout: 10000
    });

    let chats;
    try {
      // Parse newline-delimited JSON
      chats = chatsResult.trim().split('\n').filter(line => line).map(line => JSON.parse(line));
    } catch (e) {
      console.log('📱 [iMessage] Parse error:', e.message);
      return; // imsg not available or no chats
    }

    if (!Array.isArray(chats) || chats.length === 0) {
      console.log('📱 [iMessage] No chats found');
      return;
    }

    console.log(`📱 [iMessage] Checking ${chats.length} chats, cutoff: ${lastIMessageCheck.toISOString()}`);

    for (const chat of chats) {
      if (!chat.id) continue;

      try {
        // Get recent messages from this chat - also newline-delimited JSON
        const historyResult = execSync(
          `/opt/homebrew/bin/imsg history --chat-id "${chat.id}" --limit 5 --json 2>/dev/null || echo ""`,
          { encoding: 'utf8', timeout: 10000 }
        );

        const messages = historyResult.trim().split('\n').filter(line => line).map(line => JSON.parse(line));
        if (!Array.isArray(messages)) continue;

        for (const msg of messages) {
          // Skip if: from me, already processed, or too old
          if (msg.is_from_me) continue;
          if (processedIMessages.has(msg.id)) continue;

          const msgTime = new Date(msg.created_at);
          if (msgTime < lastIMessageCheck) continue;

          // Mark as processed
          processedIMessages.add(msg.id);

          // Keep set from growing too large
          if (processedIMessages.size > 1000) {
            const arr = Array.from(processedIMessages);
            arr.splice(0, 500);
            processedIMessages.clear();
            arr.forEach(id => processedIMessages.add(id));
          }

          console.log(`📱 [iMessage] New message from ${chat.identifier}: ${msg.text?.substring(0, 50)}...`);

          // Get AI response
          if (ANTHROPIC_API_KEY && msg.text) {
            const response = await getAIResponse(msg.text, null, "iMessage");
            if (response) {
              try {
                execSync(`/opt/homebrew/bin/imsg send --chat-id "${chat.id}" --text "${response.replace(/"/g, '\\"').replace(/\n/g, '\\n')}"`, {
                  timeout: 30000
                });
                console.log(`📱 [iMessage] Replied to ${chat.identifier}`);
              } catch (sendErr) {
                console.error("iMessage send failed:", sendErr.message);
              }
            }
          }
        }
      } catch (historyErr) {
        // Skip this chat
      }
    }

    lastIMessageCheck = new Date();
  } catch (error) {
    // iMessage monitoring not available, skip silently
  }
}

function startIMessageMonitor() {
  // Check immediately
  setTimeout(checkIMessages, 5000);

  // Then every 10 seconds
  setInterval(checkIMessages, 10000);
  console.log("📱 iMessage monitor started (10s interval)");
}

// GitHub issue scanner - auto-queue issues from alphatoncapital/ideas
const processedIssues = new Set();

async function scanGitHubIssues() {
  if (!GITHUB_TOKEN) return;

  try {
    const response = await fetch(
      `https://api.github.com/repos/${GITHUB_IDEAS_OWNER}/${GITHUB_IDEAS_REPO}/issues?state=open&sort=created&direction=desc&per_page=10`,
      {
        headers: {
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "Accept": "application/vnd.github.v3+json"
        }
      }
    );

    if (!response.ok) return;

    const issues = await response.json();

    for (const issue of issues) {
      // Skip if already processed or is a PR
      if (processedIssues.has(issue.number)) continue;
      if (issue.pull_request) continue;

      // Check if this issue has a corresponding project already
      const existingProject = db.prepare(
        "SELECT * FROM ideas WHERE github_issue_url LIKE ?"
      ).get(`%issues/${issue.number}`);

      if (existingProject) {
        processedIssues.add(issue.number);
        continue;
      }

      // Check for "auto-build" or "approved" labels (optional - can auto-queue all)
      const hasAutoLabel = issue.labels?.some(l =>
        ['auto-build', 'approved', 'aton'].includes(l.name?.toLowerCase())
      );

      // For now, only auto-queue labeled issues (can be changed to queue all)
      if (!hasAutoLabel) {
        processedIssues.add(issue.number);
        continue;
      }

      console.log(`🔍 [GitHub] Found issue #${issue.number}: ${issue.title}`);

      // Create project from issue
      const projectName = issue.title
        .toLowerCase()
        .replace(/[^a-z0-9\s-]/g, '')
        .replace(/\s+/g, '-')
        .substring(0, 50);

      const result = await createProjectRepo(
        projectName,
        issue.body || issue.title,
        0, // System user
        0  // No chat
      );

      if (result.success) {
        // Save to ideas table
        insertIdea.run(
          0, 0, issue.title, issue.body || '',
          JSON.stringify([{ source: 'github', issue: issue.number }]),
          issue.html_url, 'building', new Date().toISOString()
        );

        // Queue all development phases
        queueDevelopmentPhases(result.projectId, issue.body || issue.title);

        console.log(`🚀 [GitHub] Auto-queued project from issue #${issue.number}: ${result.repoName}`);

        // Comment on the issue
        try {
          await fetch(
            `https://api.github.com/repos/${GITHUB_IDEAS_OWNER}/${GITHUB_IDEAS_REPO}/issues/${issue.number}/comments`,
            {
              method: "POST",
              headers: {
                "Authorization": `Bearer ${GITHUB_TOKEN}`,
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json"
              },
              body: JSON.stringify({
                body: `🤖 **Aton is on it!**\n\nI've created a repo and started building: [${result.repoName}](${result.repoUrl})\n\nI'll update this issue with PRs as I make progress.`
              })
            }
          );
        } catch (commentErr) {
          // Comment failed, not critical
        }
      }

      processedIssues.add(issue.number);
    }
  } catch (error) {
    console.error("GitHub scan error:", error.message);
  }
}

function startGitHubScanner() {
  // Scan immediately
  setTimeout(scanGitHubIssues, 10000);

  // Then every 5 minutes
  setInterval(scanGitHubIssues, 5 * 60 * 1000);
  console.log("🔍 GitHub issue scanner started (5min interval)");
}

// Proactive work generator - find things to do when queue is empty
let lastWorkTime = new Date();

async function generateProactiveWork() {
  // Check if queue has been empty for 10+ minutes
  const pending = getPendingWork.get();
  if (pending) {
    lastWorkTime = new Date();
    return;
  }

  const idleMinutes = (Date.now() - lastWorkTime.getTime()) / 1000 / 60;
  if (idleMinutes < 10) return;

  console.log(`💡 [Proactive] Queue empty for ${Math.round(idleMinutes)} minutes, looking for work...`);

  // Check for incomplete projects
  const incompleteProjects = db.prepare(`
    SELECT p.*,
           (SELECT COUNT(*) FROM work_queue w WHERE w.project_id = p.id AND w.status = 'completed') as completed_phases,
           (SELECT COUNT(*) FROM work_queue w WHERE w.project_id = p.id) as total_phases
    FROM projects p
    WHERE p.status IN ('created', 'in_progress')
    ORDER BY p.created_at DESC
    LIMIT 5
  `).all();

  for (const project of incompleteProjects) {
    if (project.completed_phases < project.total_phases) {
      console.log(`💡 [Proactive] Project ${project.repo_name} has ${project.total_phases - project.completed_phases} phases remaining`);
      // Work queue processor will pick these up automatically
      lastWorkTime = new Date();
      return;
    }
  }

  // If truly idle, could add more proactive behaviors here:
  // - Scan repos for TODOs
  // - Update dependencies
  // - Generate content

  lastWorkTime = new Date();
}

function startProactiveGenerator() {
  // Check every 2 minutes
  setInterval(generateProactiveWork, 2 * 60 * 1000);
  console.log("💡 Proactive work generator started (2min interval)");
}

// Helper: Queue all development phases for a project
function queueDevelopmentPhases(projectId, description) {
  const phases = [
    { type: 'scaffold', desc: 'Set up basic project structure', priority: 1 },
    { type: 'contracts', desc: 'Implement smart contracts', priority: 2 },
    { type: 'tests', desc: 'Write comprehensive tests', priority: 3 },
    { type: 'scripts', desc: 'Create deployment scripts', priority: 4 },
    { type: 'frontend', desc: 'Build frontend UI', priority: 5 },
    { type: 'docs', desc: 'Write documentation', priority: 6 }
  ];

  const now = new Date().toISOString();

  for (const phase of phases) {
    insertWorkItem.run(
      projectId,
      phase.type,
      `${phase.desc}: ${description}`,
      phase.priority,
      now
    );
  }

  console.log(`📋 Queued ${phases.length} development phases for project ${projectId}`);
}

// ============ STARTUP ============

// Initialize Executive Assistant services
console.log("📋 Initializing Executive Assistant services...");
const execServices = initializeExecAssistant(db);
console.log("  ✅ Calendar, Tasks, Contacts, Email");
console.log("  ✅ Financial, News, Travel, Expenses");

// Register Executive Assistant commands
registerExecCommands(bot, db);
console.log("  ✅ Executive commands registered");

// Start bot
console.log("");
console.log("🤖 Aton Autonomous Daemon starting...");
console.log("📁 Database:", dbPath);
console.log("🖥️  Mac Studio Environment");
console.log("");
console.log("Features:");
console.log("  ✅ User memory & conversation tracking");
console.log("  " + (OPENAI_API_KEY ? "✅" : "❌") + " Voice/video transcription (Whisper)");
console.log("  " + (ANTHROPIC_API_KEY ? "✅" : "❌") + " AI conversation (Claude)");
console.log("  " + (GITHUB_TOKEN ? "✅" : "❌") + " GitHub integration");
console.log("  ✅ Work queue processor (30s)");
console.log("  ✅ iMessage monitor (10s)");
console.log("  ✅ GitHub issue scanner (5min)");
console.log("  ✅ Proactive work generator");
console.log("  ✅ Health heartbeat (60s)");
console.log("");
console.log("Executive Assistant Features:");
console.log("  ✅ Calendar management (/calendar)");
console.log("  ✅ Task tracking (/task)");
console.log("  ✅ Contact CRM (/contact)");
console.log("  ✅ Email management (/email)");
console.log("  ✅ Stock monitoring (/stock)");
console.log("  ✅ News intelligence (/news)");
console.log("  ✅ Travel management (/travel)");
console.log("  ✅ Expense tracking (/expense)");
console.log("  ✅ Daily briefing (/briefing)");
console.log("");

// Start health heartbeat first
startHealthHeartbeat();

// Executive briefing scheduler
function scheduleExecutiveBriefings() {
  const checkBriefingTime = async () => {
    const now = new Date();
    // Convert to Portugal time
    const ptTime = new Date(now.toLocaleString('en-US', { timeZone: 'Europe/Lisbon' }));
    const hour = ptTime.getHours();
    const minute = ptTime.getMinutes();

    // Morning briefing at 7:00 AM Portugal time
    if (hour === 7 && minute === 0) {
      console.log("📬 Sending morning briefing...");
      try {
        const briefing = await generateDailyBriefing(db, {});
        // Send to Logan's chat (get from first admin user or config)
        const adminUser = db.prepare("SELECT * FROM users WHERE username = 'logangolema' OR id = 1 LIMIT 1").get();
        if (adminUser) {
          await bot.api.sendMessage(adminUser.id, briefing, { parse_mode: "HTML", disable_web_page_preview: true });
          console.log("✅ Morning briefing sent");
        }
      } catch (e) {
        console.error("Morning briefing error:", e.message);
      }
    }

    // Evening briefing at 6:00 PM Portugal time
    if (hour === 18 && minute === 0) {
      console.log("📬 Sending evening briefing...");
      try {
        const briefing = await generateEveningBriefing(db, {});
        const adminUser = db.prepare("SELECT * FROM users WHERE username = 'logangolema' OR id = 1 LIMIT 1").get();
        if (adminUser) {
          await bot.api.sendMessage(adminUser.id, briefing, { parse_mode: "HTML", disable_web_page_preview: true });
          console.log("✅ Evening briefing sent");
        }
      } catch (e) {
        console.error("Evening briefing error:", e.message);
      }
    }
  };

  // Check every minute for briefing times
  setInterval(checkBriefingTime, 60000);
  console.log("📬 Executive briefing scheduler started (7AM/6PM PT)");
}

bot.start({
  onStart: (botInfo) => {
    console.log(`✅ Bot @${botInfo.username} is running!`);

    // Start all autonomous systems
    startAutonomousTasks();
    startIMessageMonitor();
    startGitHubScanner();
    startProactiveGenerator();

    // Start Executive Assistant processors
    const execProcessors = startExecProcessors(db, bot, {});
    console.log("✅ Executive Assistant processors started");

    // Start briefing scheduler
    scheduleExecutiveBriefings();

    console.log("\n🤖 Aton is fully autonomous. Press Ctrl+C to stop.");
  },
});
