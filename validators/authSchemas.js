import { z } from 'zod';

// Registration needs a real email shape and a password with real minimum strength
export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
}).strict();

// Login just needs "something was sent" — strength was already enforced at register time
export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
}).strict();
