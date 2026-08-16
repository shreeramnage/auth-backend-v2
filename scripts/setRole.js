import 'dotenv/config';
import mongoose from 'mongoose';
import User from '../models/User.js';

const [, , email, role] = process.argv;

if (!email || !role) {
  console.error('Usage: node scripts/setRole.js <email> <role>');
  process.exit(1);
}

await mongoose.connect(process.env.MONGO_URI, { dbName: 'auth-db-v2' });

const user = await User.findOneAndUpdate({ email }, { role }, { new: true });

if (!user) {
  console.error('No user found with that email');
} else {
  console.log(`${user.email} is now role: ${user.role}`);
}

await mongoose.disconnect();
