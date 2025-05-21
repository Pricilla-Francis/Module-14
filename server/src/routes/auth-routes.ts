import { Router, Request, Response } from 'express';
import { User } from '../models/user.js';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import dotenv from 'dotenv';
dotenv.config();

export const login = async (req: Request, res: Response) => {
  const { username, password } = req.body;

  try {
    // 1. Find user by username
    const user = await User.findOne({ where: { username } });

    if (!user) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // 2. Compare password using bcrypt
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // 3. Generate JWT token
    const token = jwt.sign({username: user.username },"secret",{
      expiresIn:'1h' });

    // 4. Respond with token
    return res.json({ token });

  } catch (error) {
    console.error('Login error:', error);
    return res.status(500).json({ message: 'Server error' });
  }
};


const router = Router();

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ where: { username } });

  if (!user || !await bcrypt.compare(password, user.password)) {
    res.status(401).json({ message: 'Invalid credentials' });
  }

  const token = jwt.sign({ id: user?.id }, process.env.JWT_SECRET as string, {
    expiresIn: '1h'});

  res.json({ token });
});

export default router;
