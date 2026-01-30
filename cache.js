const DEFAULT_TTL_SECONDS = Number(process.env.CACHE_TTL_SECONDS || 60);
let redisClient = null;
let redisReady = false;

const memoryCache = new Map();

async function getRedisClient() {
  if (redisClient || process.env.REDIS_URL === undefined || process.env.REDIS_URL === '') {
    return redisClient;
  }

  try {
    const { createClient } = require('redis');
    redisClient = createClient({ url: process.env.REDIS_URL });
    redisClient.on('error', () => {
      redisReady = false;
    });
    await redisClient.connect();
    redisReady = true;
  } catch (error) {
    redisClient = null;
    redisReady = false;
  }
  return redisClient;
}

async function cacheGet(key) {
  await getRedisClient();
  if (redisClient && redisReady) {
    const value = await redisClient.get(key);
    return value ? JSON.parse(value) : null;
  }

  const entry = memoryCache.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expiresAt) {
    memoryCache.delete(key);
    return null;
  }
  return entry.value;
}

async function cacheSet(key, value, ttlSeconds = DEFAULT_TTL_SECONDS) {
  await getRedisClient();
  if (redisClient && redisReady) {
    await redisClient.setEx(key, ttlSeconds, JSON.stringify(value));
    return;
  }

  memoryCache.set(key, {
    value,
    expiresAt: Date.now() + ttlSeconds * 1000
  });
}

async function withCache(key, ttlSeconds, fetcher) {
  const cached = await cacheGet(key);
  if (cached !== null) return cached;
  const data = await fetcher();
  await cacheSet(key, data, ttlSeconds);
  return data;
}

module.exports = {
  cacheGet,
  cacheSet,
  withCache,
};
