import 'dotenv/config';
import { buildApp } from './app.js';

const app = buildApp();
const PORT = parseInt(process.env.PORT ?? '3000', 10);

app.listen(PORT, () => {
  console.log(`QuestForge API running on http://localhost:${PORT}`);
});