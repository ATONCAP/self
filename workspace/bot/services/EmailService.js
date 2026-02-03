/**
 * EmailService.js - Email management for executive assistant bot
 *
 * Handles email drafting, templates, scheduling, and followup reminders
 * Uses Portugal timezone (WET/WEST) for all date calculations
 * Designed for Gmail API integration
 */

// Portugal timezone
const TIMEZONE = 'Europe/Lisbon';

// Default email templates
const DEFAULT_TEMPLATES = [
  {
    name: 'meeting_request',
    subject: 'Meeting Request: {topic}',
    body: 'Dear {name},\n\nI would like to schedule a meeting to discuss {topic}.\n\nWould {date} at {time} work for you?\n\nBest regards,\nLogan',
    variables: ['name', 'topic', 'date', 'time']
  },
  {
    name: 'thank_you',
    subject: 'Thank You - {topic}',
    body: 'Dear {name},\n\nThank you for {topic}. I really appreciate it.\n\nBest regards,\nLogan',
    variables: ['name', 'topic']
  },
  {
    name: 'follow_up',
    subject: 'Following Up: {topic}',
    body: 'Dear {name},\n\nI wanted to follow up on {topic}.\n\n{message}\n\nPlease let me know if you have any questions.\n\nBest regards,\nLogan',
    variables: ['name', 'topic', 'message']
  }
];

/**
 * Get current date in Portugal timezone
 * @returns {Date}
 */
function getPortugalNow() {
  const now = new Date();
  const ptString = now.toLocaleString('en-US', { timeZone: TIMEZONE });
  return new Date(ptString);
}

/**
 * Format a date for SQLite storage (ISO format)
 * @param {Date|string} date
 * @returns {string|null}
 */
function formatDateForDb(date) {
  if (!date) return null;
  const d = typeof date === 'string' ? new Date(date) : date;
  return d.toISOString();
}

/**
 * Get start of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getStartOfDayPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const [month, day, year] = ptString.split('/');
  return new Date(`${year}-${month}-${day}T00:00:00`);
}

/**
 * Get end of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getEndOfDayPortugal(date = new Date()) {
  const ptString = date.toLocaleString('en-US', {
    timeZone: TIMEZONE,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit'
  });
  const [month, day, year] = ptString.split('/');
  return new Date(`${year}-${month}-${day}T23:59:59`);
}

/**
 * Escape HTML special characters for Telegram
 * @param {string} text
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text) return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// =============================================================================
// DATABASE INITIALIZATION
// =============================================================================

/**
 * Initialize database tables for email management
 * @param {Database} db - better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS email_queue (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      to_address TEXT NOT NULL,
      cc_addresses TEXT,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      status TEXT DEFAULT 'draft',
      scheduled_time DATETIME,
      sent_at DATETIME,
      gmail_message_id TEXT,
      thread_id TEXT,
      error_message TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS email_templates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE,
      subject TEXT NOT NULL,
      body TEXT NOT NULL,
      variables TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS email_followups (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email_id INTEGER,
      followup_date DATETIME NOT NULL,
      reminder_sent BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (email_id) REFERENCES email_queue(id)
    );

    CREATE INDEX IF NOT EXISTS idx_email_queue_status ON email_queue(status);
    CREATE INDEX IF NOT EXISTS idx_email_queue_scheduled ON email_queue(scheduled_time);
    CREATE INDEX IF NOT EXISTS idx_email_followups_date ON email_followups(followup_date);
    CREATE INDEX IF NOT EXISTS idx_email_followups_sent ON email_followups(reminder_sent);
  `);

  // Seed default templates if they don't exist
  seedDefaultTemplates(db);
}

/**
 * Seed default email templates
 * @param {Database} db
 */
function seedDefaultTemplates(db) {
  const checkStmt = db.prepare('SELECT COUNT(*) as count FROM email_templates');
  const { count } = checkStmt.get();

  if (count === 0) {
    const insertStmt = db.prepare(`
      INSERT OR IGNORE INTO email_templates (name, subject, body, variables)
      VALUES (?, ?, ?, ?)
    `);

    for (const template of DEFAULT_TEMPLATES) {
      insertStmt.run(
        template.name,
        template.subject,
        template.body,
        JSON.stringify(template.variables)
      );
    }
  }
}

// =============================================================================
// CORE EMAIL FUNCTIONS
// =============================================================================

/**
 * Create a draft email
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.to - Recipient email address (required)
 * @param {string|Array} [params.cc] - CC addresses (string or array)
 * @param {string} params.subject - Email subject (required)
 * @param {string} params.body - Email body (required)
 * @param {Date|string} [params.scheduledTime] - When to send the email
 * @returns {Object} Created email with id
 */
function draftEmail(db, { to, cc, subject, body, scheduledTime }) {
  if (!to || typeof to !== 'string' || to.trim() === '') {
    throw new Error('Recipient email address (to) is required');
  }

  if (!subject || typeof subject !== 'string' || subject.trim() === '') {
    throw new Error('Email subject is required');
  }

  if (!body || typeof body !== 'string' || body.trim() === '') {
    throw new Error('Email body is required');
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(to.trim())) {
    throw new Error('Invalid recipient email address format');
  }

  // Process CC addresses
  let ccJson = null;
  if (cc) {
    const ccArray = Array.isArray(cc) ? cc : [cc];
    const validCc = ccArray.filter(addr => {
      if (typeof addr !== 'string') return false;
      return emailRegex.test(addr.trim());
    }).map(addr => addr.trim());
    if (validCc.length > 0) {
      ccJson = JSON.stringify(validCc);
    }
  }

  const stmt = db.prepare(`
    INSERT INTO email_queue (to_address, cc_addresses, subject, body, status, scheduled_time)
    VALUES (?, ?, ?, ?, 'draft', ?)
  `);

  const result = stmt.run(
    to.trim(),
    ccJson,
    subject.trim(),
    body.trim(),
    formatDateForDb(scheduledTime)
  );

  return getEmail(db, result.lastInsertRowid);
}

/**
 * Get a single email by ID
 * @param {Database} db
 * @param {number} emailId
 * @returns {Object|null} Email object or null if not found
 */
function getEmail(db, emailId) {
  const stmt = db.prepare('SELECT * FROM email_queue WHERE id = ?');
  const email = stmt.get(emailId);

  if (email && email.cc_addresses) {
    try {
      email.cc_addresses = JSON.parse(email.cc_addresses);
    } catch (e) {
      // Keep as string if parsing fails
    }
  }

  return email || null;
}

/**
 * Get emails by status
 * @param {Database} db
 * @param {string} status - Email status to filter by
 * @param {number} [limit=50] - Maximum number of emails to return
 * @returns {Array} Array of email objects
 */
function getEmailsByStatus(db, status, limit = 50) {
  const validStatuses = ['draft', 'pending_approval', 'approved', 'sent', 'failed'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
  }

  const stmt = db.prepare(`
    SELECT * FROM email_queue
    WHERE status = ?
    ORDER BY created_at DESC
    LIMIT ?
  `);

  const emails = stmt.all(status, limit);

  return emails.map(email => {
    if (email.cc_addresses) {
      try {
        email.cc_addresses = JSON.parse(email.cc_addresses);
      } catch (e) {
        // Keep as string if parsing fails
      }
    }
    return email;
  });
}

/**
 * Get all draft emails
 * @param {Database} db
 * @returns {Array} Array of draft emails
 */
function getDrafts(db) {
  return getEmailsByStatus(db, 'draft');
}

/**
 * Get emails pending approval
 * @param {Database} db
 * @returns {Array} Array of pending emails
 */
function getPendingEmails(db) {
  return getEmailsByStatus(db, 'pending_approval');
}

/**
 * Approve an email for sending
 * @param {Database} db
 * @param {number} emailId
 * @returns {Object} Updated email
 */
function approveEmail(db, emailId) {
  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  if (email.status !== 'draft' && email.status !== 'pending_approval') {
    throw new Error(`Cannot approve email with status '${email.status}'. Must be 'draft' or 'pending_approval'.`);
  }

  const stmt = db.prepare('UPDATE email_queue SET status = ? WHERE id = ?');
  stmt.run('approved', emailId);

  return getEmail(db, emailId);
}

/**
 * Update email content
 * @param {Database} db
 * @param {number} emailId
 * @param {Object} updates - Fields to update
 * @param {string} [updates.to] - New recipient
 * @param {string|Array} [updates.cc] - New CC addresses
 * @param {string} [updates.subject] - New subject
 * @param {string} [updates.body] - New body
 * @param {Date|string} [updates.scheduledTime] - New scheduled time
 * @param {string} [updates.status] - New status
 * @returns {Object} Updated email
 */
function updateEmail(db, emailId, updates) {
  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  // Only allow updates to draft or pending_approval emails
  if (email.status === 'sent') {
    throw new Error('Cannot update a sent email');
  }

  const allowedFields = ['to_address', 'cc_addresses', 'subject', 'body', 'scheduled_time', 'status'];
  const updateParts = [];
  const values = [];

  if (updates.to !== undefined) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(updates.to.trim())) {
      throw new Error('Invalid recipient email address format');
    }
    updateParts.push('to_address = ?');
    values.push(updates.to.trim());
  }

  if (updates.cc !== undefined) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    let ccJson = null;
    if (updates.cc) {
      const ccArray = Array.isArray(updates.cc) ? updates.cc : [updates.cc];
      const validCc = ccArray.filter(addr => {
        if (typeof addr !== 'string') return false;
        return emailRegex.test(addr.trim());
      }).map(addr => addr.trim());
      if (validCc.length > 0) {
        ccJson = JSON.stringify(validCc);
      }
    }
    updateParts.push('cc_addresses = ?');
    values.push(ccJson);
  }

  if (updates.subject !== undefined) {
    if (!updates.subject || typeof updates.subject !== 'string') {
      throw new Error('Subject must be a non-empty string');
    }
    updateParts.push('subject = ?');
    values.push(updates.subject.trim());
  }

  if (updates.body !== undefined) {
    if (!updates.body || typeof updates.body !== 'string') {
      throw new Error('Body must be a non-empty string');
    }
    updateParts.push('body = ?');
    values.push(updates.body.trim());
  }

  if (updates.scheduledTime !== undefined) {
    updateParts.push('scheduled_time = ?');
    values.push(formatDateForDb(updates.scheduledTime));
  }

  if (updates.status !== undefined) {
    const validStatuses = ['draft', 'pending_approval', 'approved', 'sent', 'failed'];
    if (!validStatuses.includes(updates.status)) {
      throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
    }
    updateParts.push('status = ?');
    values.push(updates.status);
  }

  if (updateParts.length === 0) {
    return email;
  }

  values.push(emailId);
  const stmt = db.prepare(`UPDATE email_queue SET ${updateParts.join(', ')} WHERE id = ?`);
  stmt.run(...values);

  return getEmail(db, emailId);
}

/**
 * Delete an email
 * @param {Database} db
 * @param {number} emailId
 * @returns {boolean} True if email was deleted
 */
function deleteEmail(db, emailId) {
  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  // Delete associated followups first
  const deleteFollowupsStmt = db.prepare('DELETE FROM email_followups WHERE email_id = ?');
  deleteFollowupsStmt.run(emailId);

  // Delete the email
  const deleteEmailStmt = db.prepare('DELETE FROM email_queue WHERE id = ?');
  const result = deleteEmailStmt.run(emailId);

  return result.changes > 0;
}

/**
 * Mark email as sent with Gmail IDs
 * @param {Database} db
 * @param {number} emailId
 * @param {string} gmailMessageId - Gmail message ID
 * @param {string} [threadId] - Gmail thread ID
 * @returns {Object} Updated email
 */
function markEmailSent(db, emailId, gmailMessageId, threadId = null) {
  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  const now = getPortugalNow();
  const stmt = db.prepare(`
    UPDATE email_queue
    SET status = 'sent', sent_at = ?, gmail_message_id = ?, thread_id = ?
    WHERE id = ?
  `);

  stmt.run(now.toISOString(), gmailMessageId, threadId, emailId);

  return getEmail(db, emailId);
}

/**
 * Mark email as failed
 * @param {Database} db
 * @param {number} emailId
 * @param {string} error - Error message
 * @returns {Object} Updated email
 */
function markEmailFailed(db, emailId, error) {
  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  const stmt = db.prepare(`
    UPDATE email_queue
    SET status = 'failed', error_message = ?
    WHERE id = ?
  `);

  stmt.run(error || 'Unknown error', emailId);

  return getEmail(db, emailId);
}

// =============================================================================
// FOLLOWUP FUNCTIONS
// =============================================================================

/**
 * Add a followup reminder for an email
 * @param {Database} db
 * @param {number} emailId
 * @param {Date|string} followupDate - When to remind
 * @returns {Object} Created followup with id
 */
function addFollowup(db, emailId, followupDate) {
  if (!emailId) {
    throw new Error('Email ID is required');
  }
  if (!followupDate) {
    throw new Error('Followup date is required');
  }

  const email = getEmail(db, emailId);
  if (!email) {
    throw new Error(`Email with ID ${emailId} not found`);
  }

  const stmt = db.prepare(`
    INSERT INTO email_followups (email_id, followup_date)
    VALUES (?, ?)
  `);

  const result = stmt.run(emailId, formatDateForDb(followupDate));

  const getFollowup = db.prepare('SELECT * FROM email_followups WHERE id = ?');
  return getFollowup.get(result.lastInsertRowid);
}

/**
 * Get followups due today (Portugal timezone)
 * @param {Database} db
 * @returns {Array} Array of due followups with email details
 */
function getDueFollowups(db) {
  const startOfDay = getStartOfDayPortugal();
  const endOfDay = getEndOfDayPortugal();

  const stmt = db.prepare(`
    SELECT f.*, e.to_address, e.subject, e.body, e.status as email_status,
           e.sent_at, e.gmail_message_id
    FROM email_followups f
    JOIN email_queue e ON f.email_id = e.id
    WHERE f.followup_date >= ? AND f.followup_date <= ?
    AND f.reminder_sent = 0
    ORDER BY f.followup_date ASC
  `);

  return stmt.all(startOfDay.toISOString(), endOfDay.toISOString());
}

/**
 * Mark followup reminder as sent
 * @param {Database} db
 * @param {number} followupId
 * @returns {boolean} True if followup was updated
 */
function markFollowupSent(db, followupId) {
  const stmt = db.prepare('UPDATE email_followups SET reminder_sent = 1 WHERE id = ?');
  const result = stmt.run(followupId);
  return result.changes > 0;
}

// =============================================================================
// TEMPLATE FUNCTIONS
// =============================================================================

/**
 * Create an email template
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.name - Template name (unique)
 * @param {string} params.subject - Template subject
 * @param {string} params.body - Template body
 * @param {Array} [params.variables] - Variable names used in template
 * @returns {Object} Created template with id
 */
function createTemplate(db, { name, subject, body, variables }) {
  if (!name || typeof name !== 'string' || name.trim() === '') {
    throw new Error('Template name is required');
  }

  if (!subject || typeof subject !== 'string' || subject.trim() === '') {
    throw new Error('Template subject is required');
  }

  if (!body || typeof body !== 'string' || body.trim() === '') {
    throw new Error('Template body is required');
  }

  // Check if template already exists
  const existing = getTemplate(db, name.trim());
  if (existing) {
    throw new Error(`Template with name '${name}' already exists`);
  }

  const variablesJson = variables && Array.isArray(variables)
    ? JSON.stringify(variables)
    : null;

  const stmt = db.prepare(`
    INSERT INTO email_templates (name, subject, body, variables)
    VALUES (?, ?, ?, ?)
  `);

  const result = stmt.run(
    name.trim(),
    subject.trim(),
    body.trim(),
    variablesJson
  );

  return getTemplateById(db, result.lastInsertRowid);
}

/**
 * Get a template by ID
 * @param {Database} db
 * @param {number} templateId
 * @returns {Object|null}
 */
function getTemplateById(db, templateId) {
  const stmt = db.prepare('SELECT * FROM email_templates WHERE id = ?');
  const template = stmt.get(templateId);

  if (template && template.variables) {
    try {
      template.variables = JSON.parse(template.variables);
    } catch (e) {
      // Keep as string if parsing fails
    }
  }

  return template || null;
}

/**
 * Get a template by name
 * @param {Database} db
 * @param {string} name
 * @returns {Object|null}
 */
function getTemplate(db, name) {
  if (!name || typeof name !== 'string') {
    return null;
  }

  const stmt = db.prepare('SELECT * FROM email_templates WHERE name = ?');
  const template = stmt.get(name.trim());

  if (template && template.variables) {
    try {
      template.variables = JSON.parse(template.variables);
    } catch (e) {
      // Keep as string if parsing fails
    }
  }

  return template || null;
}

/**
 * List all templates
 * @param {Database} db
 * @returns {Array} Array of template objects
 */
function getTemplates(db) {
  const stmt = db.prepare('SELECT * FROM email_templates ORDER BY name ASC');
  const templates = stmt.all();

  return templates.map(template => {
    if (template.variables) {
      try {
        template.variables = JSON.parse(template.variables);
      } catch (e) {
        // Keep as string if parsing fails
      }
    }
    return template;
  });
}

/**
 * Apply variables to a template
 * @param {Object} template - Template object with subject and body
 * @param {Object} variables - Key-value pairs of variables to replace
 * @returns {Object} Object with subject and body with variables applied
 */
function applyTemplate(template, variables) {
  if (!template || typeof template !== 'object') {
    throw new Error('Template is required');
  }

  if (!template.subject || !template.body) {
    throw new Error('Template must have subject and body');
  }

  let subject = template.subject;
  let body = template.body;

  if (variables && typeof variables === 'object') {
    for (const [key, value] of Object.entries(variables)) {
      const placeholder = `{${key}}`;
      const replacement = value !== null && value !== undefined ? String(value) : '';
      subject = subject.split(placeholder).join(replacement);
      body = body.split(placeholder).join(replacement);
    }
  }

  return { subject, body };
}

/**
 * Delete a template by name
 * @param {Database} db
 * @param {string} name
 * @returns {boolean} True if template was deleted
 */
function deleteTemplate(db, name) {
  const template = getTemplate(db, name);
  if (!template) {
    throw new Error(`Template with name '${name}' not found`);
  }

  const stmt = db.prepare('DELETE FROM email_templates WHERE name = ?');
  const result = stmt.run(name.trim());

  return result.changes > 0;
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Parse natural language email request
 * Supports patterns like:
 * - "email john@example.com about meeting tomorrow"
 * - "send email to jane@test.com subject: Project Update"
 * - "draft email for mike@company.com re: follow up"
 *
 * @param {string} text - Natural language input
 * @returns {Object|null} Parsed email object with to, subject, body suggestions
 */
function parseEmailFromText(text) {
  if (!text || typeof text !== 'string') {
    return null;
  }

  let to = null;
  let subject = null;
  let body = null;

  const normalized = text.trim();

  // Extract email address
  const emailRegex = /([^\s@]+@[^\s@]+\.[^\s@]+)/i;
  const emailMatch = normalized.match(emailRegex);
  if (emailMatch) {
    to = emailMatch[1];
  }

  // Extract subject from various patterns
  const subjectPatterns = [
    /(?:subject|subj|re|about)[:\s]+([^,\n]+)/i,
    /(?:regarding|concerning)[:\s]+([^,\n]+)/i
  ];

  for (const pattern of subjectPatterns) {
    const match = normalized.match(pattern);
    if (match) {
      subject = match[1].trim();
      break;
    }
  }

  // If no explicit subject, try to infer from context
  if (!subject) {
    // Remove common prefixes and email address
    let cleaned = normalized
      .replace(/^(?:email|send|draft|write|compose)\s+(?:email\s+)?(?:to\s+)?/i, '')
      .replace(emailRegex, '')
      .trim();

    // Remove "about" prefix if present
    cleaned = cleaned.replace(/^about\s+/i, '').trim();

    if (cleaned.length > 0 && cleaned.length < 100) {
      subject = cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
    }
  }

  // Extract body if provided (after "body:", "message:", etc.)
  const bodyPatterns = [
    /(?:body|message|content)[:\s]+(.+)$/is,
    /(?:saying|say)[:\s]+(.+)$/is
  ];

  for (const pattern of bodyPatterns) {
    const match = normalized.match(pattern);
    if (match) {
      body = match[1].trim();
      break;
    }
  }

  if (!to && !subject) {
    return null;
  }

  return {
    to,
    subject,
    body,
    raw: normalized
  };
}

/**
 * Format date for display
 * @param {string} dateStr - ISO date string
 * @returns {string} Formatted date string
 */
function formatDateForDisplay(dateStr) {
  if (!dateStr) return '';

  const date = new Date(dateStr);
  const now = getPortugalNow();
  const today = getStartOfDayPortugal(now);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const dateStart = getStartOfDayPortugal(date);

  const timeStr = date.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: TIMEZONE
  });

  if (dateStart.getTime() === today.getTime()) {
    return `Today at ${timeStr}`;
  } else if (dateStart.getTime() === tomorrow.getTime()) {
    return `Tomorrow at ${timeStr}`;
  } else {
    const dateFormatted = date.toLocaleDateString('en-GB', {
      weekday: 'short',
      day: 'numeric',
      month: 'short',
      timeZone: TIMEZONE
    });
    return `${dateFormatted} at ${timeStr}`;
  }
}

/**
 * Get status emoji for email status
 * @param {string} status
 * @returns {string} Emoji for the status
 */
function getStatusEmoji(status) {
  const emojis = {
    draft: '\u{1F4DD}',           // Memo
    pending_approval: '\u{23F3}', // Hourglass
    approved: '\u{2705}',         // Check mark
    sent: '\u{1F4E8}',            // Envelope with arrow
    failed: '\u{274C}'            // Cross mark
  };
  return emojis[status] || '\u{2753}'; // Question mark for unknown
}

/**
 * Format a single email for Telegram HTML display
 * @param {Object} email - Email object
 * @returns {string} HTML-formatted string for Telegram
 */
function formatEmailForDisplay(email) {
  if (!email) {
    return '<i>Email not found</i>';
  }

  const statusEmoji = getStatusEmoji(email.status);
  const lines = [];

  lines.push(`${statusEmoji} <b>Email #${email.id}</b>`);
  lines.push('');
  lines.push(`<b>To:</b> ${escapeHtml(email.to_address)}`);

  if (email.cc_addresses) {
    const ccList = Array.isArray(email.cc_addresses)
      ? email.cc_addresses.join(', ')
      : email.cc_addresses;
    lines.push(`<b>CC:</b> ${escapeHtml(ccList)}`);
  }

  lines.push(`<b>Subject:</b> ${escapeHtml(email.subject)}`);
  lines.push('');
  lines.push(`<b>Body:</b>`);

  // Truncate body if too long
  const maxBodyLength = 500;
  let bodyText = email.body;
  if (bodyText.length > maxBodyLength) {
    bodyText = bodyText.substring(0, maxBodyLength) + '...';
  }
  lines.push(`<pre>${escapeHtml(bodyText)}</pre>`);

  lines.push('');
  lines.push(`<b>Status:</b> ${email.status}`);

  if (email.scheduled_time) {
    lines.push(`<b>Scheduled:</b> ${formatDateForDisplay(email.scheduled_time)}`);
  }

  if (email.sent_at) {
    lines.push(`<b>Sent:</b> ${formatDateForDisplay(email.sent_at)}`);
  }

  if (email.error_message) {
    lines.push(`<b>Error:</b> <i>${escapeHtml(email.error_message)}</i>`);
  }

  lines.push(`<b>Created:</b> ${formatDateForDisplay(email.created_at)}`);

  return lines.join('\n');
}

/**
 * Format email list for Telegram HTML display
 * @param {Array} emails - Array of email objects
 * @returns {string} HTML-formatted string for Telegram
 */
function formatEmailListForDisplay(emails) {
  if (!emails || emails.length === 0) {
    return '<i>No emails found</i>';
  }

  const lines = emails.map(email => {
    const emoji = getStatusEmoji(email.status);
    let line = `${emoji} <b>#${email.id}</b> ${escapeHtml(email.subject)}`;
    line += `\n    \u{1F4E7} ${escapeHtml(email.to_address)}`;

    if (email.scheduled_time && email.status !== 'sent') {
      line += `\n    \u{1F4C5} ${formatDateForDisplay(email.scheduled_time)}`;
    }

    if (email.sent_at) {
      line += `\n    \u{2705} Sent ${formatDateForDisplay(email.sent_at)}`;
    }

    return line;
  });

  return lines.join('\n\n');
}

/**
 * Generate a one-line summary of an email
 * @param {Object} email - Email object
 * @returns {string} One-line summary
 */
function summarizeEmail(email) {
  if (!email) {
    return 'No email';
  }

  const emoji = getStatusEmoji(email.status);
  const toShort = email.to_address.split('@')[0];
  const subjectShort = email.subject.length > 30
    ? email.subject.substring(0, 27) + '...'
    : email.subject;

  return `${emoji} #${email.id}: "${subjectShort}" to ${toShort}`;
}

// =============================================================================
// GMAIL INTEGRATION (PLACEHOLDER)
// =============================================================================

/**
 * Send an email via Gmail API
 * This is a placeholder for Gmail API integration
 *
 * @param {Object} email - Email object to send
 * @param {Object} gmailAuth - Gmail authentication credentials
 * @returns {Promise<Object>} Gmail API response with messageId and threadId
 */
async function sendViaGmail(email, gmailAuth) {
  // TODO: Implement Gmail API integration
  // This will require:
  // 1. Google OAuth2 credentials
  // 2. Gmail API client initialization
  // 3. Building the email message in RFC 2822 format
  // 4. Sending via gmail.users.messages.send

  throw new Error('Gmail integration not yet implemented. Please configure Gmail API credentials.');
}

/**
 * Get approved emails ready to send
 * @param {Database} db
 * @returns {Array} Array of approved emails
 */
function getApprovedEmails(db) {
  return getEmailsByStatus(db, 'approved');
}

/**
 * Get scheduled emails that are due
 * @param {Database} db
 * @returns {Array} Array of scheduled emails due for sending
 */
function getScheduledEmailsDue(db) {
  const now = getPortugalNow();

  const stmt = db.prepare(`
    SELECT * FROM email_queue
    WHERE status = 'approved'
    AND scheduled_time IS NOT NULL
    AND scheduled_time <= ?
    ORDER BY scheduled_time ASC
  `);

  const emails = stmt.all(now.toISOString());

  return emails.map(email => {
    if (email.cc_addresses) {
      try {
        email.cc_addresses = JSON.parse(email.cc_addresses);
      } catch (e) {
        // Keep as string if parsing fails
      }
    }
    return email;
  });
}

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
  // Database initialization
  initTables,

  // Core email functions
  draftEmail,
  getEmail,
  getEmailsByStatus,
  getDrafts,
  getPendingEmails,
  approveEmail,
  updateEmail,
  deleteEmail,
  markEmailSent,
  markEmailFailed,

  // Followup functions
  addFollowup,
  getDueFollowups,
  markFollowupSent,

  // Template functions
  createTemplate,
  getTemplate,
  getTemplates,
  applyTemplate,
  deleteTemplate,

  // Helper functions
  parseEmailFromText,
  formatEmailForDisplay,
  formatEmailListForDisplay,
  summarizeEmail,
  getStatusEmoji,

  // Gmail integration
  sendViaGmail,
  getApprovedEmails,
  getScheduledEmailsDue,

  // Utility exports
  getPortugalNow,
  formatDateForDb,
  formatDateForDisplay,
  escapeHtml,

  // Constants
  TIMEZONE,
  DEFAULT_TEMPLATES
};
