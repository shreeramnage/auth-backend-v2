
import mongoose from 'mongoose';
import 'dotenv/config';
import app from './app.js';

mongoose.connect(process.env.MONGO_URI, {
  dbName: process.env.NODE_ENV === 'test' ? 'auth-db-v2-test' : 'auth-db-v2',
})
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error:', err));

const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Listening on port ${PORT}`);
});
