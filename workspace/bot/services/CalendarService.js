/**
 * CalendarService.js
 *
 * Calendar management service for the executive assistant bot.
 * Handles local database storage with structure ready for Google Calendar API integration.
 *
 * Timezone: Portugal (WET/WEST - Europe/Lisbon)
 */

const TIMEZONE = 'Europe/Lisbon';

// ============================================================================
// Database Initialization
// ============================================================================

/**
 * Initialize calendar database tables
 * @param {Object} db - Better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS calendar_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      external_id TEXT,
      title TEXT NOT NULL,
      start_time DATETIME NOT NULL,
      end_time DATETIME,
      location TEXT,
      attendees TEXT,
      description TEXT,
      reminder_sent BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS meeting_prep (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id INTEGER,
      attendee_research TEXT,
      agenda_notes TEXT,
      relevant_docs TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (event_id) REFERENCES calendar_events(id)
    );

    CREATE INDEX IF NOT EXISTS idx_events_start_time ON calendar_events(start_time);
    CREATE INDEX IF NOT EXISTS idx_events_reminder ON calendar_events(reminder_sent, start_time);
    CREATE INDEX IF NOT EXISTS idx_meeting_prep_event ON meeting_prep(event_id);
  `);
}

// ============================================================================
// Date/Time Helper Functions
// ============================================================================

/**
 * Get current date in Portugal timezone
 * @returns {Date}
 */
function getNowInTimezone() {
  return new Date(new Date().toLocaleString('en-US', { timeZone: TIMEZONE }));
}

/**
 * Get start of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getStartOfDay(date) {
  const d = new Date(date);
  d.setHours(0, 0, 0, 0);
  return d;
}

/**
 * Get end of day in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getEndOfDay(date) {
  const d = new Date(date);
  d.setHours(23, 59, 59, 999);
  return d;
}

/**
 * Get start of week (Monday) in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getStartOfWeek(date) {
  const d = new Date(date);
  const day = d.getDay();
  const diff = d.getDate() - day + (day === 0 ? -6 : 1);
  d.setDate(diff);
  d.setHours(0, 0, 0, 0);
  return d;
}

/**
 * Get end of week (Sunday) in Portugal timezone
 * @param {Date} date
 * @returns {Date}
 */
function getEndOfWeek(date) {
  const start = getStartOfWeek(date);
  const end = new Date(start);
  end.setDate(end.getDate() + 6);
  end.setHours(23, 59, 59, 999);
  return end;
}

/**
 * Parse time string like "2pm", "14:00", "2:30 PM"
 * @param {string} timeStr
 * @returns {{ hours: number, minutes: number } | null}
 */
function parseTimeString(timeStr) {
  if (!timeStr) return null;

  const cleaned = timeStr.trim().toLowerCase();

  // Try 24-hour format first: "14:00", "14:30"
  const match24 = cleaned.match(/^(\d{1,2}):(\d{2})$/);
  if (match24) {
    const hours = parseInt(match24[1], 10);
    const minutes = parseInt(match24[2], 10);
    if (hours >= 0 && hours <= 23 && minutes >= 0 && minutes <= 59) {
      return { hours, minutes };
    }
  }

  // Try 12-hour format: "2pm", "2:30pm", "2 pm", "2:30 PM"
  const match12 = cleaned.match(/^(\d{1,2})(?::(\d{2}))?\s*(am|pm)$/);
  if (match12) {
    let hours = parseInt(match12[1], 10);
    const minutes = match12[2] ? parseInt(match12[2], 10) : 0;
    const period = match12[3];

    if (hours < 1 || hours > 12 || minutes < 0 || minutes > 59) {
      return null;
    }

    if (period === 'pm' && hours !== 12) {
      hours += 12;
    } else if (period === 'am' && hours === 12) {
      hours = 0;
    }

    return { hours, minutes };
  }

  // Try just hours: "14", "9"
  const matchHour = cleaned.match(/^(\d{1,2})$/);
  if (matchHour) {
    const hours = parseInt(matchHour[1], 10);
    if (hours >= 0 && hours <= 23) {
      return { hours, minutes: 0 };
    }
  }

  return null;
}

/**
 * Parse date string like "tomorrow", "next monday", "Feb 15", "2024-02-15"
 * @param {string} dateStr
 * @returns {Date | null}
 */
function parseDateString(dateStr) {
  if (!dateStr) return null;

  const cleaned = dateStr.trim().toLowerCase();
  const now = getNowInTimezone();
  const today = getStartOfDay(now);

  // Handle relative dates
  if (cleaned === 'today') {
    return today;
  }

  if (cleaned === 'tomorrow') {
    const d = new Date(today);
    d.setDate(d.getDate() + 1);
    return d;
  }

  if (cleaned === 'yesterday') {
    const d = new Date(today);
    d.setDate(d.getDate() - 1);
    return d;
  }

  // Handle "next <weekday>" or just "<weekday>"
  const weekdays = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
  const weekdayMatch = cleaned.match(/^(?:next\s+)?(\w+)$/);
  if (weekdayMatch) {
    const dayName = weekdayMatch[1];
    const targetDay = weekdays.indexOf(dayName);

    if (targetDay !== -1) {
      const currentDay = today.getDay();
      let daysAhead = targetDay - currentDay;

      // If it's "next <day>" or the day has passed this week, go to next week
      if (cleaned.startsWith('next') || daysAhead <= 0) {
        if (daysAhead <= 0) {
          daysAhead += 7;
        }
      }

      const d = new Date(today);
      d.setDate(d.getDate() + daysAhead);
      return d;
    }
  }

  // Handle "in X days"
  const inDaysMatch = cleaned.match(/^in\s+(\d+)\s+days?$/);
  if (inDaysMatch) {
    const days = parseInt(inDaysMatch[1], 10);
    const d = new Date(today);
    d.setDate(d.getDate() + days);
    return d;
  }

  // Handle month day format: "Feb 15", "February 15", "Feb 15th"
  const months = ['january', 'february', 'march', 'april', 'may', 'june',
                  'july', 'august', 'september', 'october', 'november', 'december'];
  const monthsShort = ['jan', 'feb', 'mar', 'apr', 'may', 'jun',
                       'jul', 'aug', 'sep', 'oct', 'nov', 'dec'];

  const monthDayMatch = cleaned.match(/^(\w+)\s+(\d{1,2})(?:st|nd|rd|th)?$/);
  if (monthDayMatch) {
    const monthStr = monthDayMatch[1];
    const day = parseInt(monthDayMatch[2], 10);

    let monthIndex = months.indexOf(monthStr);
    if (monthIndex === -1) {
      monthIndex = monthsShort.indexOf(monthStr);
    }

    if (monthIndex !== -1 && day >= 1 && day <= 31) {
      const d = new Date(today);
      d.setMonth(monthIndex);
      d.setDate(day);

      // If the date has passed this year, assume next year
      if (d < today) {
        d.setFullYear(d.getFullYear() + 1);
      }

      return d;
    }
  }

  // Handle ISO format: "2024-02-15"
  const isoMatch = cleaned.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoMatch) {
    const year = parseInt(isoMatch[1], 10);
    const month = parseInt(isoMatch[2], 10) - 1;
    const day = parseInt(isoMatch[3], 10);
    return new Date(year, month, day);
  }

  // Handle DD/MM format: "15/02", "15/2"
  const ddmmMatch = cleaned.match(/^(\d{1,2})\/(\d{1,2})$/);
  if (ddmmMatch) {
    const day = parseInt(ddmmMatch[1], 10);
    const month = parseInt(ddmmMatch[2], 10) - 1;
    const d = new Date(today);
    d.setMonth(month);
    d.setDate(day);

    if (d < today) {
      d.setFullYear(d.getFullYear() + 1);
    }

    return d;
  }

  return null;
}

/**
 * Format date for display (e.g., "Today at 2:00 PM", "Tomorrow at 10:30 AM")
 * @param {Date | string} date
 * @returns {string}
 */
function formatEventTime(date) {
  const eventDate = typeof date === 'string' ? new Date(date) : date;
  const now = getNowInTimezone();
  const today = getStartOfDay(now);
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const dayAfterTomorrow = new Date(today);
  dayAfterTomorrow.setDate(dayAfterTomorrow.getDate() + 2);

  const eventDay = getStartOfDay(eventDate);
  const timeStr = eventDate.toLocaleTimeString('en-US', {
    hour: 'numeric',
    minute: '2-digit',
    hour12: true,
    timeZone: TIMEZONE
  });

  if (eventDay.getTime() === today.getTime()) {
    return `Today at ${timeStr}`;
  } else if (eventDay.getTime() === tomorrow.getTime()) {
    return `Tomorrow at ${timeStr}`;
  } else if (eventDay >= today && eventDay < dayAfterTomorrow) {
    return `Tomorrow at ${timeStr}`;
  } else {
    const dateStr = eventDate.toLocaleDateString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      timeZone: TIMEZONE
    });
    return `${dateStr} at ${timeStr}`;
  }
}

/**
 * Format date for database storage (ISO format)
 * @param {Date} date
 * @returns {string}
 */
function formatForDb(date) {
  return date.toISOString();
}

// ============================================================================
// Core Calendar Functions
// ============================================================================

/**
 * Get today's events sorted by time
 * @param {Object} db - Better-sqlite3 database instance
 * @returns {Array}
 */
function getEventsToday(db) {
  const now = getNowInTimezone();
  const startOfToday = formatForDb(getStartOfDay(now));
  const endOfToday = formatForDb(getEndOfDay(now));

  const stmt = db.prepare(`
    SELECT * FROM calendar_events
    WHERE start_time >= ? AND start_time <= ?
    ORDER BY start_time ASC
  `);

  const events = stmt.all(startOfToday, endOfToday);
  return events.map(parseEventFromDb);
}

/**
 * Get this week's events
 * @param {Object} db - Better-sqlite3 database instance
 * @returns {Array}
 */
function getEventsThisWeek(db) {
  const now = getNowInTimezone();
  const startOfWeekDate = formatForDb(getStartOfWeek(now));
  const endOfWeekDate = formatForDb(getEndOfWeek(now));

  const stmt = db.prepare(`
    SELECT * FROM calendar_events
    WHERE start_time >= ? AND start_time <= ?
    ORDER BY start_time ASC
  `);

  const events = stmt.all(startOfWeekDate, endOfWeekDate);
  return events.map(parseEventFromDb);
}

/**
 * Get events in a date range
 * @param {Object} db - Better-sqlite3 database instance
 * @param {Date} startDate
 * @param {Date} endDate
 * @returns {Array}
 */
function getEventsInRange(db, startDate, endDate) {
  const stmt = db.prepare(`
    SELECT * FROM calendar_events
    WHERE start_time >= ? AND start_time <= ?
    ORDER BY start_time ASC
  `);

  const events = stmt.all(formatForDb(startDate), formatForDb(endDate));
  return events.map(parseEventFromDb);
}

/**
 * Parse event from database row
 * @param {Object} row
 * @returns {Object}
 */
function parseEventFromDb(row) {
  return {
    ...row,
    attendees: row.attendees ? JSON.parse(row.attendees) : [],
    start_time: new Date(row.start_time),
    end_time: row.end_time ? new Date(row.end_time) : null,
    created_at: new Date(row.created_at)
  };
}

/**
 * Add a new event to the calendar
 * @param {Object} db - Better-sqlite3 database instance
 * @param {Object} event - Event details
 * @param {string} event.title - Event title
 * @param {Date|string} event.startTime - Start time
 * @param {Date|string} [event.endTime] - End time
 * @param {string} [event.location] - Location
 * @param {Array} [event.attendees] - List of attendees
 * @param {string} [event.description] - Event description
 * @param {string} [event.externalId] - External calendar ID (for future Google Calendar integration)
 * @returns {Object} Created event with ID
 */
function addEvent(db, { title, startTime, endTime, location, attendees, description, externalId }) {
  if (!title) {
    throw new Error('Event title is required');
  }
  if (!startTime) {
    throw new Error('Event start time is required');
  }

  const startTimeDate = typeof startTime === 'string' ? new Date(startTime) : startTime;
  const endTimeDate = endTime ? (typeof endTime === 'string' ? new Date(endTime) : endTime) : null;

  if (isNaN(startTimeDate.getTime())) {
    throw new Error('Invalid start time');
  }

  if (endTimeDate && isNaN(endTimeDate.getTime())) {
    throw new Error('Invalid end time');
  }

  const stmt = db.prepare(`
    INSERT INTO calendar_events (external_id, title, start_time, end_time, location, attendees, description)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    externalId || null,
    title,
    formatForDb(startTimeDate),
    endTimeDate ? formatForDb(endTimeDate) : null,
    location || null,
    attendees ? JSON.stringify(attendees) : null,
    description || null
  );

  return {
    id: result.lastInsertRowid,
    external_id: externalId || null,
    title,
    start_time: startTimeDate,
    end_time: endTimeDate,
    location: location || null,
    attendees: attendees || [],
    description: description || null,
    reminder_sent: false
  };
}

/**
 * Update an existing event
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @param {Object} updates - Fields to update
 * @returns {boolean} Success status
 */
function updateEvent(db, eventId, updates) {
  const allowedFields = ['title', 'start_time', 'end_time', 'location', 'attendees', 'description', 'external_id'];
  const setClauses = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbKey = key.replace(/([A-Z])/g, '_$1').toLowerCase(); // camelCase to snake_case
    if (allowedFields.includes(dbKey)) {
      setClauses.push(`${dbKey} = ?`);
      if (dbKey === 'attendees') {
        values.push(value ? JSON.stringify(value) : null);
      } else if (dbKey === 'start_time' || dbKey === 'end_time') {
        values.push(value ? formatForDb(new Date(value)) : null);
      } else {
        values.push(value);
      }
    }
  }

  if (setClauses.length === 0) {
    return false;
  }

  values.push(eventId);
  const stmt = db.prepare(`UPDATE calendar_events SET ${setClauses.join(', ')} WHERE id = ?`);
  const result = stmt.run(...values);

  return result.changes > 0;
}

/**
 * Delete an event
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @returns {boolean} Success status
 */
function deleteEvent(db, eventId) {
  // Delete associated meeting prep first
  const prepStmt = db.prepare('DELETE FROM meeting_prep WHERE event_id = ?');
  prepStmt.run(eventId);

  // Delete the event
  const stmt = db.prepare('DELETE FROM calendar_events WHERE id = ?');
  const result = stmt.run(eventId);

  return result.changes > 0;
}

/**
 * Get event by ID
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @returns {Object|null}
 */
function getEvent(db, eventId) {
  const stmt = db.prepare('SELECT * FROM calendar_events WHERE id = ?');
  const row = stmt.get(eventId);
  return row ? parseEventFromDb(row) : null;
}

// ============================================================================
// Reminder Functions
// ============================================================================

/**
 * Get events that need reminders
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} minutesAhead - How many minutes ahead to check
 * @returns {Array}
 */
function getUpcomingReminders(db, minutesAhead = 15) {
  const now = getNowInTimezone();
  const futureTime = new Date(now.getTime() + minutesAhead * 60 * 1000);

  const stmt = db.prepare(`
    SELECT * FROM calendar_events
    WHERE reminder_sent = 0
      AND start_time > ?
      AND start_time <= ?
    ORDER BY start_time ASC
  `);

  const events = stmt.all(formatForDb(now), formatForDb(futureTime));
  return events.map(parseEventFromDb);
}

/**
 * Mark reminder as sent for an event
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @returns {boolean} Success status
 */
function markReminderSent(db, eventId) {
  const stmt = db.prepare('UPDATE calendar_events SET reminder_sent = 1 WHERE id = ?');
  const result = stmt.run(eventId);
  return result.changes > 0;
}

// ============================================================================
// Meeting Prep Functions
// ============================================================================

/**
 * Get meeting prep materials for an event
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @returns {Object|null}
 */
function getMeetingPrep(db, eventId) {
  const stmt = db.prepare('SELECT * FROM meeting_prep WHERE event_id = ? ORDER BY created_at DESC LIMIT 1');
  const row = stmt.get(eventId);
  return row || null;
}

/**
 * Save meeting prep materials
 * @param {Object} db - Better-sqlite3 database instance
 * @param {number} eventId - Event ID
 * @param {Object} prep - Prep materials
 * @param {string} [prep.attendeeResearch] - Research on attendees
 * @param {string} [prep.agendaNotes] - Agenda notes
 * @param {string} [prep.relevantDocs] - Relevant documents
 * @returns {Object} Saved prep with ID
 */
function saveMeetingPrep(db, eventId, prep) {
  // Check if event exists
  const event = getEvent(db, eventId);
  if (!event) {
    throw new Error(`Event with ID ${eventId} not found`);
  }

  const stmt = db.prepare(`
    INSERT INTO meeting_prep (event_id, attendee_research, agenda_notes, relevant_docs)
    VALUES (?, ?, ?, ?)
  `);

  const result = stmt.run(
    eventId,
    prep.attendeeResearch || null,
    prep.agendaNotes || null,
    prep.relevantDocs || null
  );

  return {
    id: result.lastInsertRowid,
    event_id: eventId,
    attendee_research: prep.attendeeResearch || null,
    agenda_notes: prep.agendaNotes || null,
    relevant_docs: prep.relevantDocs || null
  };
}

// ============================================================================
// Natural Language Parsing
// ============================================================================

/**
 * Parse natural language event creation
 * Examples:
 *   "meeting with John tomorrow at 2pm"
 *   "call with Sarah on Monday at 10am"
 *   "lunch at 12:30 today"
 *   "dentist appointment Feb 15 at 3pm"
 *
 * @param {string} text - Natural language event description
 * @returns {Object} Parsed event details
 */
function parseEventFromText(text) {
  if (!text || typeof text !== 'string') {
    return { success: false, error: 'No text provided' };
  }

  const cleaned = text.trim();
  const lowerText = cleaned.toLowerCase();

  // Extract time
  let time = null;
  const timePatterns = [
    /at\s+(\d{1,2}(?::\d{2})?\s*(?:am|pm)?)/i,
    /(\d{1,2}(?::\d{2})?\s*(?:am|pm))/i,
    /(\d{1,2}:\d{2})/
  ];

  for (const pattern of timePatterns) {
    const match = lowerText.match(pattern);
    if (match) {
      time = parseTimeString(match[1]);
      if (time) break;
    }
  }

  // Extract date
  let date = null;
  const datePatterns = [
    /\b(today)\b/i,
    /\b(tomorrow)\b/i,
    /\b(next\s+(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday))\b/i,
    /\b(monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b/i,
    /\bon\s+(\w+\s+\d{1,2}(?:st|nd|rd|th)?)\b/i,
    /\b(\w+\s+\d{1,2}(?:st|nd|rd|th)?)\b/i,
    /\b(\d{1,2}\/\d{1,2})\b/,
    /\bin\s+(\d+)\s+days?\b/i
  ];

  for (const pattern of datePatterns) {
    const match = lowerText.match(pattern);
    if (match) {
      date = parseDateString(match[1]);
      if (date) break;
    }
  }

  // Default to today if no date found
  if (!date) {
    date = getStartOfDay(getNowInTimezone());
  }

  // Default to 9 AM if no time found
  if (!time) {
    time = { hours: 9, minutes: 0 };
  }

  // Combine date and time
  const startTime = new Date(date);
  startTime.setHours(time.hours, time.minutes, 0, 0);

  // Default end time: 1 hour later
  const endTime = new Date(startTime.getTime() + 60 * 60 * 1000);

  // Extract attendees (look for "with <name>")
  const attendees = [];
  const withMatch = lowerText.match(/with\s+([^,]+?)(?:\s+(?:on|at|tomorrow|today|next|monday|tuesday|wednesday|thursday|friday|saturday|sunday|\d))/i);
  if (withMatch) {
    const names = withMatch[1].split(/\s+and\s+|\s*,\s*/);
    for (const name of names) {
      const trimmed = name.trim();
      if (trimmed && !['the', 'a', 'an'].includes(trimmed)) {
        attendees.push(trimmed.charAt(0).toUpperCase() + trimmed.slice(1));
      }
    }
  }

  // Extract title (clean up the text)
  let title = cleaned
    .replace(/\bat\s+\d{1,2}(?::\d{2})?\s*(?:am|pm)?/gi, '')
    .replace(/\b(?:on\s+)?(?:today|tomorrow)\b/gi, '')
    .replace(/\b(?:on\s+)?(?:next\s+)?(?:monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b/gi, '')
    .replace(/\b(?:on\s+)?\w+\s+\d{1,2}(?:st|nd|rd|th)?\b/gi, '')
    .replace(/\bin\s+\d+\s+days?\b/gi, '')
    .replace(/\s+/g, ' ')
    .trim();

  // Capitalize first letter
  if (title) {
    title = title.charAt(0).toUpperCase() + title.slice(1);
  } else {
    title = 'New Event';
  }

  return {
    success: true,
    event: {
      title,
      startTime,
      endTime,
      attendees: attendees.length > 0 ? attendees : undefined
    }
  };
}

// ============================================================================
// Display Formatting
// ============================================================================

/**
 * Format events for Telegram HTML display
 * @param {Array} events - Array of events
 * @returns {string} Formatted HTML string
 */
function formatEventsForDisplay(events) {
  if (!events || events.length === 0) {
    return '<i>No events scheduled</i>';
  }

  const lines = [];
  let currentDate = null;

  for (const event of events) {
    const eventDate = event.start_time instanceof Date ? event.start_time : new Date(event.start_time);
    const dateStr = eventDate.toLocaleDateString('en-US', {
      weekday: 'long',
      month: 'short',
      day: 'numeric',
      timeZone: TIMEZONE
    });

    // Add date header if it's a new day
    if (dateStr !== currentDate) {
      if (currentDate !== null) {
        lines.push(''); // Empty line between days
      }
      lines.push(`<b>📅 ${dateStr}</b>`);
      currentDate = dateStr;
    }

    // Format time
    const timeStr = eventDate.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
      timeZone: TIMEZONE
    });

    // Format event line
    let eventLine = `  • <b>${timeStr}</b> - ${escapeHtml(event.title)}`;

    // Add location if present
    if (event.location) {
      eventLine += `\n    📍 ${escapeHtml(event.location)}`;
    }

    // Add attendees if present
    if (event.attendees && event.attendees.length > 0) {
      const attendeeList = event.attendees.map(a => escapeHtml(a)).join(', ');
      eventLine += `\n    👥 ${attendeeList}`;
    }

    lines.push(eventLine);
  }

  return lines.join('\n');
}

/**
 * Format a single event for display
 * @param {Object} event - Event object
 * @returns {string} Formatted HTML string
 */
function formatSingleEventForDisplay(event) {
  const eventDate = event.start_time instanceof Date ? event.start_time : new Date(event.start_time);

  const lines = [];
  lines.push(`<b>📌 ${escapeHtml(event.title)}</b>`);
  lines.push(`🕐 ${formatEventTime(eventDate)}`);

  if (event.end_time) {
    const endDate = event.end_time instanceof Date ? event.end_time : new Date(event.end_time);
    const endTimeStr = endDate.toLocaleTimeString('en-US', {
      hour: 'numeric',
      minute: '2-digit',
      hour12: true,
      timeZone: TIMEZONE
    });
    lines.push(`🏁 Until ${endTimeStr}`);
  }

  if (event.location) {
    lines.push(`📍 ${escapeHtml(event.location)}`);
  }

  if (event.attendees && event.attendees.length > 0) {
    const attendeeList = event.attendees.map(a => escapeHtml(a)).join(', ');
    lines.push(`👥 ${attendeeList}`);
  }

  if (event.description) {
    lines.push(`\n${escapeHtml(event.description)}`);
  }

  return lines.join('\n');
}

/**
 * Escape HTML special characters
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

// ============================================================================
// Google Calendar Integration Placeholder
// ============================================================================

/**
 * Sync events with Google Calendar (placeholder for future implementation)
 * @param {Object} db - Better-sqlite3 database instance
 * @param {Object} googleCalendarClient - Google Calendar API client
 * @returns {Promise<Object>} Sync results
 */
async function syncWithGoogleCalendar(db, googleCalendarClient) {
  // TODO: Implement Google Calendar sync
  // This function is structured to allow future integration with Google Calendar API
  //
  // Implementation steps:
  // 1. Fetch events from Google Calendar API
  // 2. Compare with local events using external_id
  // 3. Update/create/delete local events as needed
  // 4. Push local-only events to Google Calendar
  // 5. Update external_id for newly pushed events

  throw new Error('Google Calendar sync not yet implemented');
}

// ============================================================================
// Module Exports
// ============================================================================

module.exports = {
  // Database
  initTables,

  // Core calendar functions
  getEventsToday,
  getEventsThisWeek,
  getEventsInRange,
  getEvent,
  addEvent,
  updateEvent,
  deleteEvent,

  // Reminders
  getUpcomingReminders,
  markReminderSent,

  // Meeting prep
  getMeetingPrep,
  saveMeetingPrep,

  // Natural language parsing
  parseEventFromText,

  // Display formatting
  formatEventsForDisplay,
  formatSingleEventForDisplay,
  formatEventTime,

  // Helper functions
  parseTimeString,
  parseDateString,
  escapeHtml,

  // Future integrations
  syncWithGoogleCalendar,

  // Constants
  TIMEZONE
};
