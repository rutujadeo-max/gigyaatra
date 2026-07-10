/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import express from 'express';
import path from 'path';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { createServer as createViteServer } from 'vite';
import { db } from './server/db.ts';
import { computeTraitScores, evaluateGamification } from './server/scorer.ts';
import { generateRecommendations, generateMentorReply } from './server/recommender.ts';

dotenv.config();

const app = express();
app.use(express.json());

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'gigyaatra_college_demo_secret_9981';

// --- Cryptography & Auth helpers ---
function hashPassword(password: string): string {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function signToken(payload: { userId: string }): string {
  const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${signature}`;
}

function verifyToken(token: string): { userId: string } | null {
  try {
    const [header, body, signature] = token.split('.');
    const expectedSignature = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (signature !== expectedSignature) return null;
    return JSON.parse(Buffer.from(body, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

// Authentication middleware
function authenticate(req: express.Request, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Unauthorized: Missing or malformed token' });
    return;
  }

  const token = authHeader.substring(7);
  const payload = verifyToken(token);

  if (!payload) {
    res.status(401).json({ error: 'Unauthorized: Invalid token signature' });
    return;
  }

  const user = db.getUserById(payload.userId);
  if (!user) {
    res.status(401).json({ error: 'Unauthorized: User not found' });
    return;
  }

  (req as any).user = user;
  next();
}

// --- API ROUTES ---

// 1. Auth: Signup
app.post('/api/auth/signup', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    res.status(400).json({ error: 'All fields (name, email, password) are required.' });
    return;
  }

  const existing = db.getUserByEmail(email);
  if (existing) {
    res.status(400).json({ error: 'Email already registered.' });
    return;
  }

  const passwordHash = hashPassword(password);
  const user = db.createUser(name, email, passwordHash);
  const token = signToken({ userId: user.id });

  res.status(201).json({ token, user });
});

// 2. Auth: Login
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required.' });
    return;
  }

  const user = db.getUserByEmail(email);
  if (!user || user.passwordHash !== hashPassword(password)) {
    res.status(401).json({ error: 'Invalid email or password.' });
    return;
  }

  const token = signToken({ userId: user.id });
  const { passwordHash: _, ...userWithoutPassword } = user;

  res.json({ token, user: userWithoutPassword });
});

// 3. Auth: Fetch Me
app.get('/api/auth/me', authenticate, (req, res) => {
  res.json((req as any).user);
});

// 4. Start Session
app.post('/api/sessions', authenticate, (req, res) => {
  const user = (req as any).user;
  const session = db.createSession(user.id);
  res.status(201).json(session);
});

// 5. Save Zone Metrics
app.patch('/api/sessions/:id/zones/:zoneId', authenticate, (req, res) => {
  const { id, zoneId } = req.params;
  const { timeSpentSeconds, challengeAttempts, challengeCompleted, accuracyScore, choiceLog } = req.body;

  const session = db.getSessionById(id);
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  const updated = db.updateSessionZone(id, zoneId, {
    timeSpentSeconds: Number(timeSpentSeconds || 0),
    challengeAttempts: Number(challengeAttempts || 1),
    challengeCompleted: Boolean(challengeCompleted),
    accuracyScore: Number(accuracyScore || 0),
    choiceLog: choiceLog || [],
  });

  res.json(updated);
});

// 6. Complete Session (Triggering Scoring + Recommendation pipeline)
app.post('/api/sessions/:id/complete', authenticate, async (req, res) => {
  const { id } = req.params;
  const user = (req as any).user;

  const session = db.getSessionById(id);
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  try {
    // 1. Calculate traits based on zone logs
    const traitScores = computeTraitScores(session.zones);

    // 2. Compute gamified milestones (XP & Badges)
    const { xp, badges } = evaluateGamification(session.zones);

    // 3. Generate recommendations from Gemini API (with fallback if key/network issues occur)
    const recommendations = await generateRecommendations(session, user);

    // 4. Update the user's permanent record with incremental XP and unique badges
    const updatedUser = db.updateUserStats(user.id, xp, badges);

    // 5. Finalize the session record
    const updatedSession = db.completeSession(id, traitScores, recommendations, xp, badges);

    res.json({
      session: updatedSession,
      user: updatedUser,
    });
  } catch (error: any) {
    console.error('Error completing session', error);
    res.status(500).json({ error: 'Failed to process recommendation scoring', details: error.message });
  }
});

// 7. Get Session details
app.get('/api/sessions/:id', authenticate, (req, res) => {
  const { id } = req.params;
  const session = db.getSessionById(id);

  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  res.json(session);
});

// 8. Interactive Mentor Chat proxy with context injection
app.post('/api/mentor/chat', authenticate, async (req, res) => {
  const { sessionId, newMessage, chatHistory } = req.body;
  const user = (req as any).user;

  if (!sessionId || !newMessage) {
    res.status(400).json({ error: 'SessionId and newMessage are required' });
    return;
  }

  const session = db.getSessionById(sessionId);
  if (!session) {
    res.status(404).json({ error: 'Session not found' });
    return;
  }

  try {
    const reply = await generateMentorReply(chatHistory || [], session, user, newMessage);
    res.json({ reply });
  } catch (error: any) {
    console.error('Mentor chat error', error);
    res.status(500).json({ error: 'Failed to contact mentor engine', details: error.message });
  }
});

// --- CLIENT STATIC / VITE PROXIES MIDDLEWARE ---
async function startServer() {
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
}

startServer();
