/**
 * ContactService.js
 *
 * Contact and CRM management service for the executive assistant bot.
 * Handles contact storage, interaction logging, and relationship tracking.
 *
 * Uses better-sqlite3 synchronous API.
 */

/**
 * Initialize database tables for contacts and interactions
 * @param {Object} db - better-sqlite3 database instance
 */
function initTables(db) {
  // Create contacts table
  db.exec(`
    CREATE TABLE IF NOT EXISTS contacts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      company TEXT,
      title TEXT,
      email TEXT,
      phone TEXT,
      linkedin TEXT,
      notes TEXT,
      vip BOOLEAN DEFAULT 0,
      birthday DATE,
      last_contact DATETIME,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Create contact_interactions table
  db.exec(`
    CREATE TABLE IF NOT EXISTS contact_interactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      contact_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      summary TEXT,
      date DATETIME NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (contact_id) REFERENCES contacts(id)
    )
  `);

  // Create indexes for better query performance
  db.exec(`CREATE INDEX IF NOT EXISTS idx_contacts_name ON contacts(name)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_contacts_company ON contacts(company)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_contacts_vip ON contacts(vip)`);
  db.exec(`CREATE INDEX IF NOT EXISTS idx_interactions_contact ON contact_interactions(contact_id)`);
}

/**
 * Add a new contact to the database
 * @param {Object} db - better-sqlite3 database instance
 * @param {Object} contactData - Contact information
 * @param {string} contactData.name - Contact name (required)
 * @param {string} [contactData.company] - Company name
 * @param {string} [contactData.title] - Job title
 * @param {string} [contactData.email] - Email address
 * @param {string} [contactData.phone] - Phone number
 * @param {string} [contactData.linkedin] - LinkedIn URL or username
 * @param {string} [contactData.notes] - Additional notes
 * @param {boolean} [contactData.vip] - VIP status
 * @param {string} [contactData.birthday] - Birthday (YYYY-MM-DD format)
 * @returns {{id: number, name: string}}
 */
function addContact(db, { name, company, title, email, phone, linkedin, notes, vip, birthday }) {
  if (!name || typeof name !== 'string' || name.trim() === '') {
    throw new Error('Contact name is required');
  }

  const sql = `
    INSERT INTO contacts (name, company, title, email, phone, linkedin, notes, vip, birthday)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;

  const params = [
    name.trim(),
    company || null,
    title || null,
    email || null,
    phone || null,
    linkedin || null,
    notes || null,
    vip ? 1 : 0,
    birthday || null
  ];

  const stmt = db.prepare(sql);
  const result = stmt.run(...params);

  return { id: result.lastInsertRowid, name: name.trim() };
}

/**
 * Get a single contact with recent interactions
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} contactId - Contact ID
 * @returns {Object|null}
 */
function getContact(db, contactId) {
  if (!contactId || typeof contactId !== 'number') {
    throw new Error('Valid contact ID is required');
  }

  const contactStmt = db.prepare(`SELECT * FROM contacts WHERE id = ?`);
  const contact = contactStmt.get(contactId);

  if (!contact) {
    return null;
  }

  // Get recent interactions
  const interactionsStmt = db.prepare(`
    SELECT * FROM contact_interactions
    WHERE contact_id = ?
    ORDER BY date DESC
    LIMIT 5
  `);
  const interactions = interactionsStmt.all(contactId);

  contact.recentInteractions = interactions || [];
  contact.vip = Boolean(contact.vip);

  return contact;
}

/**
 * Search contacts by name, company, or email
 * @param {Object} db - better-sqlite3 database instance
 * @param {string} searchTerm - Search term
 * @returns {Array}
 */
function findContacts(db, searchTerm) {
  if (!searchTerm || typeof searchTerm !== 'string') {
    return [];
  }

  const term = `%${searchTerm.trim()}%`;

  const stmt = db.prepare(`
    SELECT * FROM contacts
    WHERE name LIKE ? OR company LIKE ? OR email LIKE ?
    ORDER BY vip DESC, name ASC
    LIMIT 50
  `);

  const contacts = stmt.all(term, term, term);

  return (contacts || []).map(c => ({
    ...c,
    vip: Boolean(c.vip)
  }));
}

/**
 * Get all VIP contacts
 * @param {Object} db - better-sqlite3 database instance
 * @returns {Array}
 */
function getVIPContacts(db) {
  const stmt = db.prepare(`
    SELECT * FROM contacts
    WHERE vip = 1
    ORDER BY name ASC
  `);

  const contacts = stmt.all();

  return (contacts || []).map(c => ({
    ...c,
    vip: true
  }));
}

/**
 * Update contact details
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} contactId - Contact ID
 * @param {Object} updates - Fields to update
 * @returns {boolean}
 */
function updateContact(db, contactId, updates) {
  if (!contactId || typeof contactId !== 'number') {
    throw new Error('Valid contact ID is required');
  }

  if (!updates || typeof updates !== 'object' || Object.keys(updates).length === 0) {
    throw new Error('Updates object is required');
  }

  const allowedFields = ['name', 'company', 'title', 'email', 'phone', 'linkedin', 'notes', 'vip', 'birthday', 'last_contact'];
  const updateFields = [];
  const params = [];

  for (const [key, value] of Object.entries(updates)) {
    if (allowedFields.includes(key)) {
      updateFields.push(`${key} = ?`);
      if (key === 'vip') {
        params.push(value ? 1 : 0);
      } else {
        params.push(value);
      }
    }
  }

  if (updateFields.length === 0) {
    throw new Error('No valid fields to update');
  }

  params.push(contactId);

  const sql = `UPDATE contacts SET ${updateFields.join(', ')} WHERE id = ?`;
  const stmt = db.prepare(sql);
  const result = stmt.run(...params);

  return result.changes > 0;
}

/**
 * Delete a contact and their interactions
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} contactId - Contact ID
 * @returns {boolean}
 */
function deleteContact(db, contactId) {
  if (!contactId || typeof contactId !== 'number') {
    throw new Error('Valid contact ID is required');
  }

  // Delete interactions first
  const deleteInteractionsStmt = db.prepare(`DELETE FROM contact_interactions WHERE contact_id = ?`);
  deleteInteractionsStmt.run(contactId);

  // Delete contact
  const deleteContactStmt = db.prepare(`DELETE FROM contacts WHERE id = ?`);
  const result = deleteContactStmt.run(contactId);

  return result.changes > 0;
}

/**
 * Log an interaction with a contact
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} contactId - Contact ID
 * @param {Object} interaction - Interaction details
 * @param {string} interaction.type - Type of interaction (meeting, email, call, message)
 * @param {string} [interaction.summary] - Summary of the interaction
 * @param {string} [interaction.date] - Date of interaction (defaults to now)
 * @returns {{id: number}}
 */
function logInteraction(db, contactId, { type, summary, date }) {
  if (!contactId || typeof contactId !== 'number') {
    throw new Error('Valid contact ID is required');
  }

  const validTypes = ['meeting', 'email', 'call', 'message'];
  if (!type || !validTypes.includes(type.toLowerCase())) {
    throw new Error(`Invalid interaction type. Must be one of: ${validTypes.join(', ')}`);
  }

  const interactionDate = date || new Date().toISOString();

  // Insert interaction
  const insertStmt = db.prepare(`
    INSERT INTO contact_interactions (contact_id, type, summary, date)
    VALUES (?, ?, ?, ?)
  `);
  const result = insertStmt.run(contactId, type.toLowerCase(), summary || null, interactionDate);
  const interactionId = result.lastInsertRowid;

  // Update last_contact on the contact
  try {
    const updateStmt = db.prepare(`UPDATE contacts SET last_contact = ? WHERE id = ?`);
    updateStmt.run(interactionDate, contactId);
  } catch (err) {
    console.error('Failed to update last_contact:', err);
  }

  return { id: interactionId };
}

/**
 * Get interaction history for a contact
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} contactId - Contact ID
 * @param {number} [limit=20] - Maximum number of interactions to return
 * @returns {Array}
 */
function getInteractionHistory(db, contactId, limit = 20) {
  if (!contactId || typeof contactId !== 'number') {
    throw new Error('Valid contact ID is required');
  }

  const stmt = db.prepare(`
    SELECT * FROM contact_interactions
    WHERE contact_id = ?
    ORDER BY date DESC
    LIMIT ?
  `);

  const interactions = stmt.all(contactId, limit);
  return interactions || [];
}

/**
 * Get contacts with upcoming birthdays
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} [daysAhead=30] - Number of days to look ahead
 * @returns {Array}
 */
function getUpcomingBirthdays(db, daysAhead = 30) {
  // SQLite date handling for birthdays - compare month and day
  const stmt = db.prepare(`
    SELECT *,
      CASE
        WHEN strftime('%m-%d', birthday) >= strftime('%m-%d', 'now')
        THEN julianday(strftime('%Y', 'now') || '-' || strftime('%m-%d', birthday)) - julianday('now')
        ELSE julianday(strftime('%Y', 'now', '+1 year') || '-' || strftime('%m-%d', birthday)) - julianday('now')
      END as days_until
    FROM contacts
    WHERE birthday IS NOT NULL
    HAVING days_until >= 0 AND days_until <= ?
    ORDER BY days_until ASC
  `);

  const contacts = stmt.all(daysAhead);

  return (contacts || []).map(c => ({
    ...c,
    vip: Boolean(c.vip),
    days_until: Math.round(c.days_until)
  }));
}

/**
 * Get contacts not contacted within specified days
 * @param {Object} db - better-sqlite3 database instance
 * @param {number} [days=30] - Number of days threshold
 * @returns {Array}
 */
function getContactsNotContactedSince(db, days = 30) {
  const stmt = db.prepare(`
    SELECT *,
      CASE
        WHEN last_contact IS NULL THEN 9999
        ELSE julianday('now') - julianday(last_contact)
      END as days_since_contact
    FROM contacts
    WHERE last_contact IS NULL
      OR julianday('now') - julianday(last_contact) > ?
    ORDER BY vip DESC, days_since_contact DESC
  `);

  const contacts = stmt.all(days);

  return (contacts || []).map(c => ({
    ...c,
    vip: Boolean(c.vip),
    days_since_contact: c.days_since_contact === 9999 ? null : Math.round(c.days_since_contact)
  }));
}

/**
 * Get emoji for interaction type
 * @param {string} type - Interaction type
 * @returns {string}
 */
function getInteractionTypeEmoji(type) {
  const emojis = {
    meeting: '🤝',
    email: '📧',
    call: '📞',
    message: '💬'
  };
  return emojis[type?.toLowerCase()] || '📌';
}

/**
 * Format a contact for Telegram HTML display
 * @param {Object} contact - Contact object
 * @returns {string}
 */
function formatContactForDisplay(contact) {
  if (!contact) {
    return 'Contact not found.';
  }

  const lines = [];

  // Header with VIP indicator
  const vipBadge = contact.vip ? ' ⭐ VIP' : '';
  lines.push(`<b>${escapeHtml(contact.name)}</b>${vipBadge}`);

  // Title and company
  if (contact.title || contact.company) {
    const titleParts = [];
    if (contact.title) titleParts.push(escapeHtml(contact.title));
    if (contact.company) titleParts.push(`at ${escapeHtml(contact.company)}`);
    lines.push(titleParts.join(' '));
  }

  lines.push(''); // Empty line for spacing

  // Contact details
  if (contact.email) {
    lines.push(`📧 ${escapeHtml(contact.email)}`);
  }
  if (contact.phone) {
    lines.push(`📞 ${escapeHtml(contact.phone)}`);
  }
  if (contact.linkedin) {
    lines.push(`🔗 ${escapeHtml(contact.linkedin)}`);
  }
  if (contact.birthday) {
    lines.push(`🎂 ${escapeHtml(contact.birthday)}`);
  }

  // Last contact info
  if (contact.last_contact) {
    const lastContactDate = new Date(contact.last_contact);
    const formattedDate = lastContactDate.toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
    lines.push(`📅 Last contact: ${formattedDate}`);
  }

  // Notes
  if (contact.notes) {
    lines.push('');
    lines.push(`📝 <i>${escapeHtml(contact.notes)}</i>`);
  }

  // Recent interactions
  if (contact.recentInteractions && contact.recentInteractions.length > 0) {
    lines.push('');
    lines.push('<b>Recent Interactions:</b>');
    for (const interaction of contact.recentInteractions) {
      const emoji = getInteractionTypeEmoji(interaction.type);
      const date = new Date(interaction.date).toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric'
      });
      const summary = interaction.summary ? ` - ${escapeHtml(interaction.summary)}` : '';
      lines.push(`${emoji} ${date}${summary}`);
    }
  }

  return lines.join('\n');
}

/**
 * Format a list of contacts for display
 * @param {Array} contacts - Array of contact objects
 * @returns {string}
 */
function formatContactListForDisplay(contacts) {
  if (!contacts || contacts.length === 0) {
    return 'No contacts found.';
  }

  const lines = [`<b>Contacts (${contacts.length})</b>`, ''];

  for (const contact of contacts) {
    const vipBadge = contact.vip ? ' ⭐' : '';
    const company = contact.company ? ` - ${escapeHtml(contact.company)}` : '';
    lines.push(`• <b>${escapeHtml(contact.name)}</b>${vipBadge}${company}`);

    if (contact.title) {
      lines.push(`  ${escapeHtml(contact.title)}`);
    }

    // Show days since contact if available
    if (contact.days_since_contact !== undefined) {
      if (contact.days_since_contact === null) {
        lines.push(`  <i>Never contacted</i>`);
      } else {
        lines.push(`  <i>Last contact: ${contact.days_since_contact} days ago</i>`);
      }
    }

    // Show days until birthday if available
    if (contact.days_until !== undefined) {
      if (contact.days_until === 0) {
        lines.push(`  🎂 <b>Birthday today!</b>`);
      } else if (contact.days_until === 1) {
        lines.push(`  🎂 Birthday tomorrow`);
      } else {
        lines.push(`  🎂 Birthday in ${contact.days_until} days`);
      }
    }

    lines.push(`  [ID: ${contact.id}]`);
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Parse natural language text to extract contact information
 * @param {string} text - Natural language text describing a contact
 * @returns {Object} - Parsed contact data
 */
function parseContactFromText(text) {
  if (!text || typeof text !== 'string') {
    return { name: '' };
  }

  const contact = {};
  const normalizedText = text.trim();

  // Try to extract email
  const emailMatch = normalizedText.match(/[\w.-]+@[\w.-]+\.\w+/i);
  if (emailMatch) {
    contact.email = emailMatch[0];
  }

  // Try to extract phone (various formats)
  const phoneMatch = normalizedText.match(/(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}/);
  if (phoneMatch) {
    contact.phone = phoneMatch[0];
  }

  // Try to extract LinkedIn URL
  const linkedinMatch = normalizedText.match(/(?:linkedin\.com\/in\/[\w-]+|@[\w-]+)/i);
  if (linkedinMatch) {
    contact.linkedin = linkedinMatch[0];
  }

  // Try to extract birthday (various formats)
  const birthdayPatterns = [
    /birthday[:\s]+(\d{4}-\d{2}-\d{2})/i,
    /birthday[:\s]+(\d{1,2}\/\d{1,2}\/\d{4})/i,
    /born[:\s]+(\d{4}-\d{2}-\d{2})/i
  ];

  for (const pattern of birthdayPatterns) {
    const match = normalizedText.match(pattern);
    if (match) {
      contact.birthday = match[1];
      break;
    }
  }

  // Check for VIP indicators
  if (/\bvip\b|\bimportant\b|\bkey\s+contact\b/i.test(normalizedText)) {
    contact.vip = true;
  }

  // Try to extract company (common patterns)
  const companyPatterns = [
    /(?:at|@|from|works?\s+(?:at|for))\s+([A-Z][A-Za-z0-9\s&.-]+?)(?:\s+as\s+|\s*,|$)/i,
    /company[:\s]+([A-Za-z0-9\s&.-]+?)(?:\s*,|$)/i
  ];

  for (const pattern of companyPatterns) {
    const match = normalizedText.match(pattern);
    if (match) {
      contact.company = match[1].trim();
      break;
    }
  }

  // Try to extract title
  const titlePatterns = [
    /(?:as|title[:\s])\s*(?:a\s+)?([A-Z][A-Za-z\s]+?(?:Officer|Director|Manager|Engineer|Developer|Designer|Lead|Head|VP|CEO|CTO|CFO|COO|President|Analyst|Consultant))/i,
    /([A-Z][A-Za-z\s]+?(?:Officer|Director|Manager|Engineer|Developer|Designer|Lead|Head|VP|CEO|CTO|CFO|COO|President|Analyst|Consultant))\s+(?:at|@|from)/i
  ];

  for (const pattern of titlePatterns) {
    const match = normalizedText.match(pattern);
    if (match) {
      contact.title = match[1].trim();
      break;
    }
  }

  // Extract name - this is tricky, try to get the first capitalized words
  // Remove already extracted parts to help isolate the name
  let nameText = normalizedText;
  if (contact.email) nameText = nameText.replace(contact.email, '');
  if (contact.phone) nameText = nameText.replace(contact.phone, '');
  if (contact.linkedin) nameText = nameText.replace(contact.linkedin, '');

  // Common patterns for names
  const namePatterns = [
    /^([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/,  // "John Smith"
    /name[:\s]+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/i,  // "name: John Smith"
    /add\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)+)/i  // "add John Smith"
  ];

  for (const pattern of namePatterns) {
    const match = nameText.match(pattern);
    if (match) {
      contact.name = match[1].trim();
      break;
    }
  }

  // If no name found, use first few words that look like a name
  if (!contact.name) {
    const words = nameText.trim().split(/\s+/);
    const nameWords = [];
    for (const word of words) {
      if (/^[A-Z][a-z]+$/.test(word) && nameWords.length < 3) {
        nameWords.push(word);
      } else if (nameWords.length > 0) {
        break;
      }
    }
    if (nameWords.length > 0) {
      contact.name = nameWords.join(' ');
    }
  }

  // Extract notes - anything after "notes:" or remaining descriptive text
  const notesMatch = normalizedText.match(/notes?[:\s]+(.+)/i);
  if (notesMatch) {
    contact.notes = notesMatch[1].trim();
  }

  return contact;
}

/**
 * Escape HTML special characters for Telegram
 * @param {string} text - Text to escape
 * @returns {string}
 */
function escapeHtml(text) {
  if (!text) return '';
  return String(text)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

module.exports = {
  initTables,
  addContact,
  getContact,
  findContacts,
  getVIPContacts,
  updateContact,
  deleteContact,
  logInteraction,
  getInteractionHistory,
  getUpcomingBirthdays,
  getContactsNotContactedSince,
  formatContactForDisplay,
  formatContactListForDisplay,
  parseContactFromText,
  getInteractionTypeEmoji
};
