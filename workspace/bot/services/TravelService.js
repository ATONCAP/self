/**
 * TravelService.js - Travel management for executive assistant
 *
 * Handles travel itineraries, segments, documents, and search functionality
 * Uses Portugal timezone (WET/WEST) for all date calculations
 */

// Portugal timezone
const TIMEZONE = 'Europe/Lisbon';

// =============================================================================
// UTILITY FUNCTIONS
// =============================================================================

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
 * Format a date for display
 * @param {string} dateStr - ISO date string
 * @returns {string}
 */
function formatDateForDisplay(dateStr) {
  if (!dateStr) return '';

  const date = new Date(dateStr);
  const now = getPortugalNow();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const tomorrow = new Date(today);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const dateOnly = new Date(date.getFullYear(), date.getMonth(), date.getDate());

  const timeStr = date.toLocaleTimeString('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    timeZone: TIMEZONE
  });

  if (dateOnly.getTime() === today.getTime()) {
    return `Today at ${timeStr}`;
  } else if (dateOnly.getTime() === tomorrow.getTime()) {
    return `Tomorrow at ${timeStr}`;
  } else {
    const dateFormatted = date.toLocaleDateString('en-GB', {
      weekday: 'short',
      day: 'numeric',
      month: 'short',
      year: 'numeric',
      timeZone: TIMEZONE
    });
    return `${dateFormatted} at ${timeStr}`;
  }
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

/**
 * Parse JSON safely
 * @param {string} jsonStr
 * @returns {Object|null}
 */
function safeParseJson(jsonStr) {
  if (!jsonStr) return null;
  try {
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

// =============================================================================
// DATABASE INITIALIZATION
// =============================================================================

/**
 * Initialize database tables for travel management
 * @param {Database} db - better-sqlite3 database instance
 */
function initTables(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS travel_itineraries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      trip_name TEXT NOT NULL,
      destination TEXT,
      start_date DATE NOT NULL,
      end_date DATE NOT NULL,
      status TEXT DEFAULT 'planned',
      notes TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS travel_segments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      itinerary_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      confirmation_number TEXT,
      details TEXT,
      start_time DATETIME NOT NULL,
      end_time DATETIME,
      location TEXT,
      cost REAL,
      currency TEXT DEFAULT 'USD',
      status TEXT DEFAULT 'pending',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (itinerary_id) REFERENCES travel_itineraries(id)
    );

    CREATE TABLE IF NOT EXISTS travel_documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      document_type TEXT NOT NULL,
      document_number TEXT,
      country TEXT,
      expiry_date DATE,
      reminder_sent BOOLEAN DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_travel_itineraries_status ON travel_itineraries(status);
    CREATE INDEX IF NOT EXISTS idx_travel_itineraries_dates ON travel_itineraries(start_date, end_date);
    CREATE INDEX IF NOT EXISTS idx_travel_segments_itinerary ON travel_segments(itinerary_id);
    CREATE INDEX IF NOT EXISTS idx_travel_segments_type ON travel_segments(type);
    CREATE INDEX IF NOT EXISTS idx_travel_segments_start_time ON travel_segments(start_time);
    CREATE INDEX IF NOT EXISTS idx_travel_documents_expiry ON travel_documents(expiry_date);
  `);
}

// =============================================================================
// ITINERARY FUNCTIONS
// =============================================================================

/**
 * Create a new travel itinerary
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.tripName - Trip name (required)
 * @param {string} [params.destination] - Destination
 * @param {Date|string} params.startDate - Start date (required)
 * @param {Date|string} params.endDate - End date (required)
 * @param {string} [params.notes] - Additional notes
 * @returns {Object} Created itinerary with id
 */
function createItinerary(db, { tripName, destination, startDate, endDate, notes }) {
  if (!tripName || typeof tripName !== 'string' || tripName.trim() === '') {
    throw new Error('Trip name is required');
  }
  if (!startDate) {
    throw new Error('Start date is required');
  }
  if (!endDate) {
    throw new Error('End date is required');
  }

  const start = new Date(startDate);
  const end = new Date(endDate);

  if (end < start) {
    throw new Error('End date must be after start date');
  }

  const stmt = db.prepare(`
    INSERT INTO travel_itineraries (trip_name, destination, start_date, end_date, notes)
    VALUES (?, ?, ?, ?, ?)
  `);

  const result = stmt.run(
    tripName.trim(),
    destination || null,
    formatDateForDb(startDate),
    formatDateForDb(endDate),
    notes || null
  );

  return getItinerary(db, result.lastInsertRowid);
}

/**
 * Get itinerary by ID with all segments
 * @param {Database} db
 * @param {number} itineraryId
 * @returns {Object|null} Itinerary with segments array
 */
function getItinerary(db, itineraryId) {
  const itineraryStmt = db.prepare('SELECT * FROM travel_itineraries WHERE id = ?');
  const itinerary = itineraryStmt.get(itineraryId);

  if (!itinerary) {
    return null;
  }

  const segments = getSegmentsByItinerary(db, itineraryId);

  return {
    ...itinerary,
    segments
  };
}

/**
 * Get upcoming trips starting within N days
 * @param {Database} db
 * @param {number} [daysAhead=30] - Number of days to look ahead
 * @returns {Array} Array of itineraries
 */
function getUpcomingTrips(db, daysAhead = 30) {
  const now = getPortugalNow();
  const futureDate = new Date(now);
  futureDate.setDate(futureDate.getDate() + daysAhead);

  const stmt = db.prepare(`
    SELECT * FROM travel_itineraries
    WHERE start_date >= ? AND start_date <= ?
    AND status NOT IN ('completed', 'cancelled')
    ORDER BY start_date ASC
  `);

  return stmt.all(now.toISOString(), futureDate.toISOString());
}

/**
 * Get currently active trip (status = in_progress)
 * @param {Database} db
 * @returns {Object|null} Current trip with segments or null
 */
function getCurrentTrip(db) {
  const stmt = db.prepare(`
    SELECT * FROM travel_itineraries
    WHERE status = 'in_progress'
    ORDER BY start_date ASC
    LIMIT 1
  `);

  const itinerary = stmt.get();

  if (!itinerary) {
    return null;
  }

  const segments = getSegmentsByItinerary(db, itinerary.id);

  return {
    ...itinerary,
    segments
  };
}

/**
 * Update itinerary details
 * @param {Database} db
 * @param {number} itineraryId
 * @param {Object} updates - Fields to update
 * @returns {Object} Updated itinerary
 */
function updateItinerary(db, itineraryId, updates) {
  const itinerary = getItinerary(db, itineraryId);
  if (!itinerary) {
    throw new Error(`Itinerary with ID ${itineraryId} not found`);
  }

  const allowedFields = ['trip_name', 'destination', 'start_date', 'end_date', 'notes', 'status'];
  const fieldMapping = {
    tripName: 'trip_name',
    startDate: 'start_date',
    endDate: 'end_date'
  };

  const setClauses = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbField = fieldMapping[key] || key;
    if (allowedFields.includes(dbField)) {
      setClauses.push(`${dbField} = ?`);
      if (dbField.includes('date')) {
        values.push(formatDateForDb(value));
      } else {
        values.push(value);
      }
    }
  }

  if (setClauses.length === 0) {
    return getItinerary(db, itineraryId);
  }

  values.push(itineraryId);
  const stmt = db.prepare(`UPDATE travel_itineraries SET ${setClauses.join(', ')} WHERE id = ?`);
  stmt.run(...values);

  return getItinerary(db, itineraryId);
}

/**
 * Update itinerary status
 * @param {Database} db
 * @param {number} itineraryId
 * @param {string} status - New status
 * @returns {Object} Updated itinerary
 */
function updateItineraryStatus(db, itineraryId, status) {
  const validStatuses = ['planned', 'booked', 'in_progress', 'completed', 'cancelled'];
  if (!validStatuses.includes(status)) {
    throw new Error(`Invalid status. Must be one of: ${validStatuses.join(', ')}`);
  }

  const itinerary = getItinerary(db, itineraryId);
  if (!itinerary) {
    throw new Error(`Itinerary with ID ${itineraryId} not found`);
  }

  const stmt = db.prepare('UPDATE travel_itineraries SET status = ? WHERE id = ?');
  stmt.run(status, itineraryId);

  return getItinerary(db, itineraryId);
}

/**
 * Delete itinerary and all its segments
 * @param {Database} db
 * @param {number} itineraryId
 * @returns {boolean} True if deleted
 */
function deleteItinerary(db, itineraryId) {
  const itinerary = getItinerary(db, itineraryId);
  if (!itinerary) {
    throw new Error(`Itinerary with ID ${itineraryId} not found`);
  }

  // Delete segments first
  const deleteSegmentsStmt = db.prepare('DELETE FROM travel_segments WHERE itinerary_id = ?');
  deleteSegmentsStmt.run(itineraryId);

  // Delete itinerary
  const deleteItineraryStmt = db.prepare('DELETE FROM travel_itineraries WHERE id = ?');
  const result = deleteItineraryStmt.run(itineraryId);

  return result.changes > 0;
}

// =============================================================================
// SEGMENT FUNCTIONS
// =============================================================================

/**
 * Add a travel segment to an itinerary
 * @param {Database} db
 * @param {number} itineraryId
 * @param {Object} params
 * @param {string} params.type - Segment type: flight, hotel, car, train, meeting
 * @param {string} [params.confirmationNumber] - Confirmation/booking number
 * @param {Object} [params.details] - Type-specific details (stored as JSON)
 * @param {Date|string} params.startTime - Start time (required)
 * @param {Date|string} [params.endTime] - End time
 * @param {string} [params.location] - Location
 * @param {number} [params.cost] - Cost amount
 * @param {string} [params.currency='USD'] - Currency code
 * @returns {Object} Created segment
 */
function addSegment(db, itineraryId, { type, confirmationNumber, details, startTime, endTime, location, cost, currency = 'USD' }) {
  const validTypes = ['flight', 'hotel', 'car', 'train', 'meeting'];
  if (!type || !validTypes.includes(type)) {
    throw new Error(`Invalid segment type. Must be one of: ${validTypes.join(', ')}`);
  }
  if (!startTime) {
    throw new Error('Start time is required');
  }

  // Verify itinerary exists
  const itineraryStmt = db.prepare('SELECT id FROM travel_itineraries WHERE id = ?');
  const itinerary = itineraryStmt.get(itineraryId);
  if (!itinerary) {
    throw new Error(`Itinerary with ID ${itineraryId} not found`);
  }

  const stmt = db.prepare(`
    INSERT INTO travel_segments
    (itinerary_id, type, confirmation_number, details, start_time, end_time, location, cost, currency)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const detailsJson = details ? JSON.stringify(details) : null;

  const result = stmt.run(
    itineraryId,
    type,
    confirmationNumber || null,
    detailsJson,
    formatDateForDb(startTime),
    formatDateForDb(endTime),
    location || null,
    cost || null,
    currency
  );

  return getSegment(db, result.lastInsertRowid);
}

/**
 * Get a single segment by ID
 * @param {Database} db
 * @param {number} segmentId
 * @returns {Object|null} Segment object with parsed details
 */
function getSegment(db, segmentId) {
  const stmt = db.prepare('SELECT * FROM travel_segments WHERE id = ?');
  const segment = stmt.get(segmentId);

  if (!segment) {
    return null;
  }

  return {
    ...segment,
    details: safeParseJson(segment.details)
  };
}

/**
 * Get all segments for an itinerary
 * @param {Database} db
 * @param {number} itineraryId
 * @returns {Array} Array of segments sorted by start_time
 */
function getSegmentsByItinerary(db, itineraryId) {
  const stmt = db.prepare(`
    SELECT * FROM travel_segments
    WHERE itinerary_id = ?
    ORDER BY start_time ASC
  `);

  const segments = stmt.all(itineraryId);

  return segments.map(segment => ({
    ...segment,
    details: safeParseJson(segment.details)
  }));
}

/**
 * Update a segment
 * @param {Database} db
 * @param {number} segmentId
 * @param {Object} updates - Fields to update
 * @returns {Object} Updated segment
 */
function updateSegment(db, segmentId, updates) {
  const segment = getSegment(db, segmentId);
  if (!segment) {
    throw new Error(`Segment with ID ${segmentId} not found`);
  }

  const allowedFields = ['type', 'confirmation_number', 'details', 'start_time', 'end_time', 'location', 'cost', 'currency', 'status'];
  const fieldMapping = {
    confirmationNumber: 'confirmation_number',
    startTime: 'start_time',
    endTime: 'end_time'
  };

  const setClauses = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbField = fieldMapping[key] || key;
    if (allowedFields.includes(dbField)) {
      setClauses.push(`${dbField} = ?`);
      if (dbField === 'details') {
        values.push(value ? JSON.stringify(value) : null);
      } else if (dbField.includes('time')) {
        values.push(formatDateForDb(value));
      } else {
        values.push(value);
      }
    }
  }

  if (setClauses.length === 0) {
    return getSegment(db, segmentId);
  }

  values.push(segmentId);
  const stmt = db.prepare(`UPDATE travel_segments SET ${setClauses.join(', ')} WHERE id = ?`);
  stmt.run(...values);

  return getSegment(db, segmentId);
}

/**
 * Delete a segment
 * @param {Database} db
 * @param {number} segmentId
 * @returns {boolean} True if deleted
 */
function deleteSegment(db, segmentId) {
  const segment = getSegment(db, segmentId);
  if (!segment) {
    throw new Error(`Segment with ID ${segmentId} not found`);
  }

  const stmt = db.prepare('DELETE FROM travel_segments WHERE id = ?');
  const result = stmt.run(segmentId);

  return result.changes > 0;
}

/**
 * Get upcoming flights departing within N hours
 * @param {Database} db
 * @param {number} [hoursAhead=24] - Hours to look ahead
 * @returns {Array} Array of flight segments with itinerary info
 */
function getUpcomingFlights(db, hoursAhead = 24) {
  const now = getPortugalNow();
  const futureTime = new Date(now);
  futureTime.setHours(futureTime.getHours() + hoursAhead);

  const stmt = db.prepare(`
    SELECT s.*, i.trip_name, i.destination as trip_destination
    FROM travel_segments s
    JOIN travel_itineraries i ON s.itinerary_id = i.id
    WHERE s.type = 'flight'
    AND s.start_time >= ? AND s.start_time <= ?
    AND s.status != 'cancelled'
    ORDER BY s.start_time ASC
  `);

  const flights = stmt.all(now.toISOString(), futureTime.toISOString());

  return flights.map(flight => ({
    ...flight,
    details: safeParseJson(flight.details)
  }));
}

// =============================================================================
// DOCUMENT FUNCTIONS
// =============================================================================

/**
 * Add a travel document
 * @param {Database} db
 * @param {Object} params
 * @param {string} params.documentType - Document type: passport, visa, id, insurance
 * @param {string} [params.documentNumber] - Document number
 * @param {string} [params.country] - Issuing country
 * @param {Date|string} [params.expiryDate] - Expiry date
 * @returns {Object} Created document
 */
function addDocument(db, { documentType, documentNumber, country, expiryDate }) {
  const validTypes = ['passport', 'visa', 'id', 'insurance'];
  if (!documentType || !validTypes.includes(documentType)) {
    throw new Error(`Invalid document type. Must be one of: ${validTypes.join(', ')}`);
  }

  const stmt = db.prepare(`
    INSERT INTO travel_documents (document_type, document_number, country, expiry_date)
    VALUES (?, ?, ?, ?)
  `);

  const result = stmt.run(
    documentType,
    documentNumber || null,
    country || null,
    formatDateForDb(expiryDate)
  );

  const getDoc = db.prepare('SELECT * FROM travel_documents WHERE id = ?');
  return getDoc.get(result.lastInsertRowid);
}

/**
 * Get all travel documents
 * @param {Database} db
 * @returns {Array} Array of documents
 */
function getDocuments(db) {
  const stmt = db.prepare(`
    SELECT * FROM travel_documents
    ORDER BY expiry_date ASC NULLS LAST
  `);

  return stmt.all();
}

/**
 * Get documents expiring within N days
 * @param {Database} db
 * @param {number} [daysAhead=90] - Days to look ahead
 * @returns {Array} Array of expiring documents
 */
function getExpiringDocuments(db, daysAhead = 90) {
  const now = getPortugalNow();
  const futureDate = new Date(now);
  futureDate.setDate(futureDate.getDate() + daysAhead);

  const stmt = db.prepare(`
    SELECT * FROM travel_documents
    WHERE expiry_date IS NOT NULL
    AND expiry_date <= ?
    AND reminder_sent = 0
    ORDER BY expiry_date ASC
  `);

  return stmt.all(futureDate.toISOString());
}

/**
 * Update a document
 * @param {Database} db
 * @param {number} documentId
 * @param {Object} updates - Fields to update
 * @returns {Object} Updated document
 */
function updateDocument(db, documentId, updates) {
  const getDoc = db.prepare('SELECT * FROM travel_documents WHERE id = ?');
  const document = getDoc.get(documentId);
  if (!document) {
    throw new Error(`Document with ID ${documentId} not found`);
  }

  const allowedFields = ['document_type', 'document_number', 'country', 'expiry_date'];
  const fieldMapping = {
    documentType: 'document_type',
    documentNumber: 'document_number',
    expiryDate: 'expiry_date'
  };

  const setClauses = [];
  const values = [];

  for (const [key, value] of Object.entries(updates)) {
    const dbField = fieldMapping[key] || key;
    if (allowedFields.includes(dbField)) {
      setClauses.push(`${dbField} = ?`);
      if (dbField.includes('date')) {
        values.push(formatDateForDb(value));
      } else {
        values.push(value);
      }
    }
  }

  if (setClauses.length === 0) {
    return document;
  }

  values.push(documentId);
  const stmt = db.prepare(`UPDATE travel_documents SET ${setClauses.join(', ')} WHERE id = ?`);
  stmt.run(...values);

  return getDoc.get(documentId);
}

/**
 * Mark document reminder as sent
 * @param {Database} db
 * @param {number} documentId
 * @returns {boolean} True if updated
 */
function markDocumentReminderSent(db, documentId) {
  const stmt = db.prepare('UPDATE travel_documents SET reminder_sent = 1 WHERE id = ?');
  const result = stmt.run(documentId);
  return result.changes > 0;
}

// =============================================================================
// FLIGHT/HOTEL SEARCH (MOCK - READY FOR AMADEUS API)
// =============================================================================

/**
 * Search for flights (mock implementation, ready for Amadeus API)
 * @param {string} origin - Origin airport code
 * @param {string} destination - Destination airport code
 * @param {Date|string} date - Departure date
 * @param {string} [apiKey] - API key for real implementation
 * @returns {Promise<Array>} Array of flight options
 */
async function searchFlights(origin, destination, date, apiKey = null) {
  if (!origin || !destination || !date) {
    throw new Error('Origin, destination, and date are required');
  }

  // TODO: Implement actual Amadeus API call when apiKey is provided
  // For now, return mock data
  if (apiKey) {
    // Placeholder for real API implementation
    // const response = await fetch(`https://api.amadeus.com/v2/shopping/flight-offers?...`);
    console.log('Amadeus API integration pending - using mock data');
  }

  const departureDate = new Date(date);
  const departureStr = departureDate.toISOString().split('T')[0];

  return [
    {
      id: 'mock-flight-1',
      airline: 'TAP Portugal',
      flightNumber: 'TP123',
      origin: origin.toUpperCase(),
      destination: destination.toUpperCase(),
      departureTime: `${departureStr}T08:30:00`,
      arrivalTime: `${departureStr}T11:45:00`,
      duration: '3h 15m',
      price: { amount: 299.00, currency: 'EUR' },
      cabinClass: 'economy',
      stops: 0
    },
    {
      id: 'mock-flight-2',
      airline: 'Lufthansa',
      flightNumber: 'LH456',
      origin: origin.toUpperCase(),
      destination: destination.toUpperCase(),
      departureTime: `${departureStr}T14:00:00`,
      arrivalTime: `${departureStr}T17:30:00`,
      duration: '3h 30m',
      price: { amount: 349.00, currency: 'EUR' },
      cabinClass: 'economy',
      stops: 0
    },
    {
      id: 'mock-flight-3',
      airline: 'Air France',
      flightNumber: 'AF789',
      origin: origin.toUpperCase(),
      destination: destination.toUpperCase(),
      departureTime: `${departureStr}T19:15:00`,
      arrivalTime: `${departureStr}T23:00:00`,
      duration: '3h 45m',
      price: { amount: 275.00, currency: 'EUR' },
      cabinClass: 'economy',
      stops: 1
    }
  ];
}

/**
 * Search for hotels (mock implementation, ready for Amadeus API)
 * @param {string} destination - City or location
 * @param {Date|string} checkIn - Check-in date
 * @param {Date|string} checkOut - Check-out date
 * @param {string} [apiKey] - API key for real implementation
 * @returns {Promise<Array>} Array of hotel options
 */
async function searchHotels(destination, checkIn, checkOut, apiKey = null) {
  if (!destination || !checkIn || !checkOut) {
    throw new Error('Destination, check-in, and check-out dates are required');
  }

  // TODO: Implement actual Amadeus API call when apiKey is provided
  if (apiKey) {
    console.log('Amadeus API integration pending - using mock data');
  }

  const checkInDate = new Date(checkIn);
  const checkOutDate = new Date(checkOut);
  const nights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));

  return [
    {
      id: 'mock-hotel-1',
      name: `Grand Hotel ${destination}`,
      address: `123 Main Street, ${destination}`,
      rating: 4.5,
      stars: 5,
      checkIn: checkInDate.toISOString().split('T')[0],
      checkOut: checkOutDate.toISOString().split('T')[0],
      nights: nights,
      price: { amount: 199.00 * nights, currency: 'EUR', perNight: 199.00 },
      amenities: ['wifi', 'breakfast', 'pool', 'gym', 'spa'],
      roomType: 'Deluxe King'
    },
    {
      id: 'mock-hotel-2',
      name: `${destination} City Inn`,
      address: `456 Central Ave, ${destination}`,
      rating: 4.2,
      stars: 4,
      checkIn: checkInDate.toISOString().split('T')[0],
      checkOut: checkOutDate.toISOString().split('T')[0],
      nights: nights,
      price: { amount: 129.00 * nights, currency: 'EUR', perNight: 129.00 },
      amenities: ['wifi', 'breakfast', 'parking'],
      roomType: 'Standard Queen'
    },
    {
      id: 'mock-hotel-3',
      name: `Budget Stay ${destination}`,
      address: `789 Economy Blvd, ${destination}`,
      rating: 3.8,
      stars: 3,
      checkIn: checkInDate.toISOString().split('T')[0],
      checkOut: checkOutDate.toISOString().split('T')[0],
      nights: nights,
      price: { amount: 79.00 * nights, currency: 'EUR', perNight: 79.00 },
      amenities: ['wifi'],
      roomType: 'Standard Twin'
    }
  ];
}

// =============================================================================
// DISPLAY FUNCTIONS
// =============================================================================

/**
 * Get emoji for segment type
 * @param {string} type
 * @returns {string}
 */
function getSegmentTypeEmoji(type) {
  const emojis = {
    flight: '\u{2708}\u{FE0F}',     // Airplane
    hotel: '\u{1F3E8}',              // Hotel
    car: '\u{1F697}',                // Car
    train: '\u{1F686}',              // Train
    meeting: '\u{1F4BC}'             // Briefcase
  };
  return emojis[type] || '\u{1F4CD}'; // Pin as default
}

/**
 * Get emoji for status
 * @param {string} status
 * @returns {string}
 */
function getStatusEmoji(status) {
  const emojis = {
    planned: '\u{1F4DD}',     // Memo
    booked: '\u{2705}',       // Check mark
    pending: '\u{23F3}',      // Hourglass
    confirmed: '\u{2705}',    // Check mark
    in_progress: '\u{1F3C3}', // Running
    completed: '\u{1F3C1}',   // Checkered flag
    cancelled: '\u{274C}'     // X
  };
  return emojis[status] || '\u{2753}'; // Question mark as default
}

/**
 * Format flight details for display
 * @param {Object} details - Flight details object
 * @returns {string}
 */
function formatFlightDetails(details) {
  if (!details) return '';

  const lines = [];

  if (details.airline) {
    lines.push(`\u{2708}\u{FE0F} ${escapeHtml(details.airline)}`);
  }
  if (details.flightNumber) {
    lines.push(`Flight: ${escapeHtml(details.flightNumber)}`);
  }
  if (details.origin && details.destination) {
    lines.push(`Route: ${escapeHtml(details.origin)} \u{2192} ${escapeHtml(details.destination)}`);
  }
  if (details.terminal) {
    lines.push(`Terminal: ${escapeHtml(details.terminal)}`);
  }
  if (details.gate) {
    lines.push(`Gate: ${escapeHtml(details.gate)}`);
  }
  if (details.seat) {
    lines.push(`Seat: ${escapeHtml(details.seat)}`);
  }
  if (details.cabinClass) {
    lines.push(`Class: ${escapeHtml(details.cabinClass)}`);
  }

  return lines.join('\n');
}

/**
 * Format hotel details for display
 * @param {Object} details - Hotel details object
 * @returns {string}
 */
function formatHotelDetails(details) {
  if (!details) return '';

  const lines = [];

  if (details.hotelName) {
    lines.push(`\u{1F3E8} ${escapeHtml(details.hotelName)}`);
  }
  if (details.address) {
    lines.push(`\u{1F4CD} ${escapeHtml(details.address)}`);
  }
  if (details.roomType) {
    lines.push(`Room: ${escapeHtml(details.roomType)}`);
  }
  if (details.checkInTime) {
    lines.push(`Check-in: ${escapeHtml(details.checkInTime)}`);
  }
  if (details.checkOutTime) {
    lines.push(`Check-out: ${escapeHtml(details.checkOutTime)}`);
  }
  if (details.amenities && Array.isArray(details.amenities)) {
    lines.push(`Amenities: ${details.amenities.map(a => escapeHtml(a)).join(', ')}`);
  }

  return lines.join('\n');
}

/**
 * Format a single segment for display
 * @param {Object} segment
 * @returns {string} HTML-formatted string
 */
function formatSegmentForDisplay(segment) {
  if (!segment) return '';

  const typeEmoji = getSegmentTypeEmoji(segment.type);
  const statusEmoji = getStatusEmoji(segment.status);

  let output = `${typeEmoji} <b>${escapeHtml(segment.type.charAt(0).toUpperCase() + segment.type.slice(1))}</b> ${statusEmoji}\n`;

  if (segment.confirmation_number) {
    output += `\u{1F4CB} Confirmation: <code>${escapeHtml(segment.confirmation_number)}</code>\n`;
  }

  output += `\u{1F4C5} ${formatDateForDisplay(segment.start_time)}`;
  if (segment.end_time) {
    output += ` - ${formatDateForDisplay(segment.end_time)}`;
  }
  output += '\n';

  if (segment.location) {
    output += `\u{1F4CD} ${escapeHtml(segment.location)}\n`;
  }

  // Format type-specific details
  if (segment.details) {
    if (segment.type === 'flight') {
      const flightInfo = formatFlightDetails(segment.details);
      if (flightInfo) output += flightInfo + '\n';
    } else if (segment.type === 'hotel') {
      const hotelInfo = formatHotelDetails(segment.details);
      if (hotelInfo) output += hotelInfo + '\n';
    }
  }

  if (segment.cost) {
    output += `\u{1F4B0} ${segment.cost} ${segment.currency}\n`;
  }

  output += `<code>#seg${segment.id}</code>`;

  return output;
}

/**
 * Format full itinerary for display
 * @param {Object} itinerary - Itinerary with segments
 * @returns {string} HTML-formatted string
 */
function formatItineraryForDisplay(itinerary) {
  if (!itinerary) return '<i>Itinerary not found</i>';

  const statusEmoji = getStatusEmoji(itinerary.status);
  const duration = calculateTripDuration(itinerary.start_date, itinerary.end_date);

  let output = `\u{1F30D} <b>${escapeHtml(itinerary.trip_name)}</b> ${statusEmoji}\n`;

  if (itinerary.destination) {
    output += `\u{1F4CD} ${escapeHtml(itinerary.destination)}\n`;
  }

  const startDate = new Date(itinerary.start_date).toLocaleDateString('en-GB', {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: TIMEZONE
  });
  const endDate = new Date(itinerary.end_date).toLocaleDateString('en-GB', {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    year: 'numeric',
    timeZone: TIMEZONE
  });

  output += `\u{1F4C5} ${startDate} - ${endDate} (${duration} days)\n`;

  if (itinerary.notes) {
    output += `\u{1F4DD} ${escapeHtml(itinerary.notes)}\n`;
  }

  output += `<code>#trip${itinerary.id}</code>\n`;

  // Add segments
  if (itinerary.segments && itinerary.segments.length > 0) {
    output += '\n<b>--- Segments ---</b>\n\n';
    output += itinerary.segments.map(seg => formatSegmentForDisplay(seg)).join('\n\n');
  } else {
    output += '\n<i>No segments added yet</i>';
  }

  return output;
}

/**
 * Format upcoming trips list for display
 * @param {Array} trips
 * @returns {string} HTML-formatted string
 */
function formatUpcomingTripsForDisplay(trips) {
  if (!trips || trips.length === 0) {
    return '<i>No upcoming trips</i>';
  }

  const lines = trips.map(trip => {
    const statusEmoji = getStatusEmoji(trip.status);
    const duration = calculateTripDuration(trip.start_date, trip.end_date);

    const startDate = new Date(trip.start_date).toLocaleDateString('en-GB', {
      day: 'numeric',
      month: 'short',
      timeZone: TIMEZONE
    });

    let line = `${statusEmoji} <b>${escapeHtml(trip.trip_name)}</b>`;
    if (trip.destination) {
      line += ` \u{2192} ${escapeHtml(trip.destination)}`;
    }
    line += `\n    \u{1F4C5} ${startDate} (${duration} days)`;
    line += `\n    <code>#trip${trip.id}</code>`;

    return line;
  });

  return lines.join('\n\n');
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

/**
 * Calculate trip duration in days
 * @param {Date|string} startDate
 * @param {Date|string} endDate
 * @returns {number} Number of days
 */
function calculateTripDuration(startDate, endDate) {
  if (!startDate || !endDate) return 0;

  const start = new Date(startDate);
  const end = new Date(endDate);
  const diffMs = end - start;
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24));

  return Math.max(1, diffDays);
}

/**
 * Parse itinerary from natural language text
 * Supports patterns like:
 * - "trip to NYC Feb 10-15"
 * - "Paris trip March 5 to March 12"
 * - "business trip London 2024-03-01 to 2024-03-05"
 *
 * @param {string} text - Natural language input
 * @returns {Object|null} Parsed itinerary object or null
 */
function parseItineraryFromText(text) {
  if (!text || typeof text !== 'string') {
    return null;
  }

  let tripName = text.trim();
  let destination = null;
  let startDate = null;
  let endDate = null;

  const now = getPortugalNow();
  const currentYear = now.getFullYear();

  // Pattern: "trip to DESTINATION DATE_RANGE"
  const tripToPattern = /(?:trip\s+to|visit(?:ing)?|going\s+to)\s+([A-Za-z\s]+?)(?:\s+(?:from\s+)?(\w+\s+\d{1,2}(?:st|nd|rd|th)?)\s*[-–to]+\s*(\w+\s+\d{1,2}(?:st|nd|rd|th)?|\d{1,2}(?:st|nd|rd|th)?))/i;

  // Pattern: "DESTINATION trip DATE_RANGE"
  const destTripPattern = /([A-Za-z\s]+?)\s+trip\s+(?:from\s+)?(\w+\s+\d{1,2}(?:st|nd|rd|th)?)\s*[-–to]+\s*(\w+\s+\d{1,2}(?:st|nd|rd|th)?|\d{1,2}(?:st|nd|rd|th)?)/i;

  // Pattern: ISO date format "YYYY-MM-DD to YYYY-MM-DD"
  const isoDatePattern = /(\d{4}-\d{2}-\d{2})\s*(?:to|-)\s*(\d{4}-\d{2}-\d{2})/i;

  // Try trip to pattern
  let match = tripToPattern.exec(text);
  if (match) {
    destination = match[1].trim();
    tripName = `Trip to ${destination}`;
    startDate = parseFlexibleDate(match[2], currentYear);
    endDate = parseFlexibleDate(match[3], currentYear, startDate);
  }

  // Try destination trip pattern
  if (!match) {
    match = destTripPattern.exec(text);
    if (match) {
      destination = match[1].trim();
      tripName = `${destination} Trip`;
      startDate = parseFlexibleDate(match[2], currentYear);
      endDate = parseFlexibleDate(match[3], currentYear, startDate);
    }
  }

  // Try ISO date pattern
  if (!startDate) {
    match = isoDatePattern.exec(text);
    if (match) {
      startDate = new Date(match[1]);
      endDate = new Date(match[2]);

      // Extract destination if mentioned
      const destMatch = text.match(/(?:to|in|at)\s+([A-Za-z\s]+?)(?:\s+\d|$)/i);
      if (destMatch) {
        destination = destMatch[1].trim();
        tripName = `Trip to ${destination}`;
      }
    }
  }

  // Simple destination extraction if no dates found
  if (!startDate) {
    const simpleDestMatch = text.match(/(?:trip\s+to|visit(?:ing)?)\s+([A-Za-z\s]+)/i);
    if (simpleDestMatch) {
      destination = simpleDestMatch[1].trim();
      tripName = `Trip to ${destination}`;
    }
  }

  if (!tripName || tripName === text.trim()) {
    return null;
  }

  return {
    tripName,
    destination,
    startDate,
    endDate
  };
}

/**
 * Parse flexible date formats
 * @param {string} dateStr - Date string like "Feb 10" or "March 15th"
 * @param {number} year - Year to use
 * @param {Date} [referenceDate] - Reference date for relative parsing
 * @returns {Date|null}
 */
function parseFlexibleDate(dateStr, year, referenceDate = null) {
  if (!dateStr) return null;

  const months = {
    jan: 0, january: 0,
    feb: 1, february: 1,
    mar: 2, march: 2,
    apr: 3, april: 3,
    may: 4,
    jun: 5, june: 5,
    jul: 6, july: 6,
    aug: 7, august: 7,
    sep: 8, september: 8,
    oct: 9, october: 9,
    nov: 10, november: 10,
    dec: 11, december: 11
  };

  // Remove ordinal suffixes
  const cleaned = dateStr.toLowerCase().replace(/(\d+)(?:st|nd|rd|th)/g, '$1');

  // Try "Month Day" format
  const monthDayMatch = cleaned.match(/([a-z]+)\s+(\d{1,2})/i);
  if (monthDayMatch) {
    const monthName = monthDayMatch[1].toLowerCase();
    const day = parseInt(monthDayMatch[2], 10);

    if (months[monthName] !== undefined && day >= 1 && day <= 31) {
      return new Date(year, months[monthName], day);
    }
  }

  // Try just day (use reference month)
  const dayOnlyMatch = cleaned.match(/^(\d{1,2})$/);
  if (dayOnlyMatch && referenceDate) {
    const day = parseInt(dayOnlyMatch[1], 10);
    const refMonth = referenceDate.getMonth();
    let refYear = referenceDate.getFullYear();

    // If day is less than reference day, might be next month
    if (day < referenceDate.getDate()) {
      const nextMonth = refMonth + 1;
      if (nextMonth > 11) {
        return new Date(refYear + 1, 0, day);
      }
      return new Date(refYear, nextMonth, day);
    }

    return new Date(refYear, refMonth, day);
  }

  return null;
}

// =============================================================================
// MODULE EXPORTS
// =============================================================================

module.exports = {
  // Database
  initTables,

  // Itinerary functions
  createItinerary,
  getItinerary,
  getUpcomingTrips,
  getCurrentTrip,
  updateItinerary,
  updateItineraryStatus,
  deleteItinerary,

  // Segment functions
  addSegment,
  getSegment,
  getSegmentsByItinerary,
  updateSegment,
  deleteSegment,
  getUpcomingFlights,

  // Document functions
  addDocument,
  getDocuments,
  getExpiringDocuments,
  updateDocument,
  markDocumentReminderSent,

  // Search functions (mock for now)
  searchFlights,
  searchHotels,

  // Display functions
  formatItineraryForDisplay,
  formatSegmentForDisplay,
  formatUpcomingTripsForDisplay,
  getSegmentTypeEmoji,
  getStatusEmoji,
  formatFlightDetails,
  formatHotelDetails,

  // Helper functions
  parseItineraryFromText,
  calculateTripDuration,

  // Utility exports
  getPortugalNow,
  formatDateForDb,
  formatDateForDisplay,
  escapeHtml,

  // Constants
  TIMEZONE
};
