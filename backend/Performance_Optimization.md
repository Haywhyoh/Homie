# HoodMe Performance Optimization

## Overview
This document outlines comprehensive performance optimization strategies for HoodMe, covering database optimization, caching strategies, API performance, and Nigerian network considerations.

## Database Performance Optimization

### Database Configuration

#### PostgreSQL Optimization
```sql
-- postgresql.conf optimizations for production
-- Memory settings
shared_buffers = 256MB                    -- 25% of RAM for small servers
effective_cache_size = 1GB                -- 75% of RAM
work_mem = 4MB                           -- Per connection work memory
maintenance_work_mem = 64MB              -- For VACUUM, CREATE INDEX

-- Connection settings
max_connections = 200                    -- Based on expected load
connection_limit = 180                   -- Reserve some connections

-- WAL settings
wal_buffers = 16MB
checkpoint_segments = 32
checkpoint_completion_target = 0.9

-- Query planning
random_page_cost = 1.1                  -- SSD storage assumption
effective_io_concurrency = 200          -- For SSD

-- Logging and monitoring
log_statement = 'mod'                   -- Log modifications
log_min_duration_statement = 1000       -- Log slow queries (1 second)
log_checkpoints = on
log_connections = on
log_disconnections = on
```

### Critical Database Indexes

#### Performance-Critical Indexes
```sql
-- User authentication indexes
CREATE UNIQUE INDEX CONCURRENTLY idx_users_phone_number 
ON users(phone_number) WHERE phone_number IS NOT NULL;

CREATE UNIQUE INDEX CONCURRENTLY idx_users_email 
ON users(email) WHERE email IS NOT NULL;

CREATE INDEX CONCURRENTLY idx_user_sessions_user_id_active 
ON user_sessions(user_id) WHERE is_active = true;

-- Geolocation indexes (PostGIS)
CREATE INDEX CONCURRENTLY idx_user_locations_point 
ON user_locations USING GIST(ST_Point(longitude, latitude)) 
WHERE is_current = true;

CREATE INDEX CONCURRENTLY idx_neighborhoods_boundary 
ON neighborhoods USING GIST(ST_GeomFromGeoJSON(boundary_coordinates));

CREATE INDEX CONCURRENTLY idx_neighborhoods_center_point 
ON neighborhoods USING GIST(ST_Point(center_longitude, center_latitude)) 
WHERE is_verified = true;

-- Social feed indexes
CREATE INDEX CONCURRENTLY idx_posts_neighborhood_created_approved 
ON posts(neighborhood_id, created_at DESC) 
WHERE is_approved = true AND moderation_status = 'approved';

CREATE INDEX CONCURRENTLY idx_posts_category_neighborhood 
ON posts(category_id, neighborhood_id, created_at DESC) 
WHERE is_approved = true;

CREATE INDEX CONCURRENTLY idx_post_reactions_post_user 
ON post_reactions(post_id, user_id);

CREATE INDEX CONCURRENTLY idx_post_comments_post_created 
ON post_comments(post_id, created_at DESC) 
WHERE is_approved = true;

-- Messaging indexes
CREATE INDEX CONCURRENTLY idx_messages_conversation_created 
ON messages(conversation_id, created_at DESC) 
WHERE is_deleted = false;

CREATE INDEX CONCURRENTLY idx_conversation_participants_user 
ON conversation_participants(user_id, conversation_id) 
WHERE left_at IS NULL;

CREATE INDEX CONCURRENTLY idx_messages_unread 
ON message_read_receipts(user_id, read_at) 
WHERE read_at IS NULL;

-- Marketplace indexes
CREATE INDEX CONCURRENTLY idx_marketplace_location_available 
ON marketplace_listings USING GIST(
  ST_Point(
    CAST(location_details->>'longitude' AS FLOAT), 
    CAST(location_details->>'latitude' AS FLOAT)
  )
) WHERE availability_status = 'available';

CREATE INDEX CONCURRENTLY idx_marketplace_category_price 
ON marketplace_listings(category_id, price, created_at DESC) 
WHERE availability_status = 'available';

-- Events indexes
CREATE INDEX CONCURRENTLY idx_events_neighborhood_date_active 
ON events(neighborhood_id, start_datetime) 
WHERE is_cancelled = false AND start_datetime > NOW();

CREATE INDEX CONCURRENTLY idx_event_rsvps_user_status 
ON event_rsvps(user_id, rsvp_status, event_id);

-- Notification indexes
CREATE INDEX CONCURRENTLY idx_notifications_user_unread 
ON notifications(user_id, created_at DESC) 
WHERE read_at IS NULL;

-- Analytics indexes
CREATE INDEX CONCURRENTLY idx_user_activities_user_type_created 
ON user_activities(user_id, activity_type, created_at DESC);

CREATE INDEX CONCURRENTLY idx_business_metrics_type_date 
ON business_metrics(metric_type, date_recorded DESC);
```

### Query Optimization

#### Optimized Query Patterns
```typescript
class OptimizedQueries {
  // Optimized neighborhood feed query
  async getNeighborhoodFeed(
    neighborhoodId: string, 
    userId: string, 
    limit: number = 20, 
    cursor?: string
  ) {
    const query = `
      WITH user_neighborhood_check AS (
        SELECT 1 FROM user_neighborhoods 
        WHERE user_id = $1 AND neighborhood_id = $2
      ),
      feed_posts AS (
        SELECT 
          p.id,
          p.title,
          p.content,
          p.created_at,
          p.updated_at,
          u.id as author_id,
          u.first_name,
          u.last_name,
          u.profile_picture_url,
          pc.name as category_name,
          pc.color_code,
          -- Get reaction counts efficiently
          (
            SELECT jsonb_object_agg(reaction_type, count)
            FROM (
              SELECT reaction_type, COUNT(*)::int as count
              FROM post_reactions 
              WHERE post_id = p.id 
              GROUP BY reaction_type
            ) reaction_counts
          ) as reactions,
          -- Get user's reaction if any
          (
            SELECT reaction_type 
            FROM post_reactions 
            WHERE post_id = p.id AND user_id = $1
          ) as user_reaction,
          -- Get comment count
          (
            SELECT COUNT(*)::int 
            FROM post_comments 
            WHERE post_id = p.id AND is_approved = true
          ) as comments_count
        FROM posts p
        JOIN users u ON p.user_id = u.id
        JOIN post_categories pc ON p.category_id = pc.id
        WHERE p.neighborhood_id = $2
          AND p.is_approved = true 
          AND p.moderation_status = 'approved'
          AND ($3::timestamp IS NULL OR p.created_at < $3::timestamp)
          AND EXISTS (SELECT 1 FROM user_neighborhood_check)
        ORDER BY p.created_at DESC
        LIMIT $4
      )
      SELECT 
        fp.*,
        COALESCE(
          (
            SELECT jsonb_agg(
              jsonb_build_object(
                'type', media_type,
                'url', file_url,
                'thumbnail_url', thumbnail_url
              ) ORDER BY upload_order
            )
            FROM post_media 
            WHERE post_id = fp.id
          ), 
          '[]'::jsonb
        ) as media
      FROM feed_posts fp
      ORDER BY fp.created_at DESC;
    `;
    
    const cursorDate = cursor ? new Date(cursor) : null;
    return this.database.query(query, [userId, neighborhoodId, cursorDate, limit]);
  }
  
  // Optimized user search with geolocation
  async searchNearbyUsers(
    searchQuery: string,
    userLat: number,
    userLng: number,
    radiusKm: number = 5,
    limit: number = 20
  ) {
    const query = `
      WITH nearby_neighborhoods AS (
        SELECT n.id
        FROM neighborhoods n
        WHERE ST_DWithin(
          ST_Point(n.center_longitude, n.center_latitude)::geography,
          ST_Point($2, $3)::geography,
          $4 * 1000  -- Convert km to meters
        )
      ),
      matching_users AS (
        SELECT DISTINCT
          u.id,
          u.first_name,
          u.last_name,
          u.profile_picture_url,
          -- Calculate relevance score
          (
            CASE 
              WHEN LOWER(u.first_name || ' ' || u.last_name) LIKE LOWER($1) THEN 100
              WHEN LOWER(u.first_name) LIKE LOWER($1 || '%') THEN 80
              WHEN LOWER(u.last_name) LIKE LOWER($1 || '%') THEN 80
              WHEN LOWER(u.first_name || ' ' || u.last_name) LIKE LOWER('%' || $1 || '%') THEN 60
              ELSE 40
            END
          ) as relevance_score,
          -- Get neighborhoods
          (
            SELECT jsonb_agg(n.name)
            FROM user_neighborhoods un
            JOIN neighborhoods n ON un.neighborhood_id = n.id
            WHERE un.user_id = u.id
          ) as neighborhoods
        FROM users u
        JOIN user_neighborhoods un ON u.id = un.user_id
        WHERE un.neighborhood_id IN (SELECT id FROM nearby_neighborhoods)
          AND u.is_active = true
          AND u.is_verified = true
          AND (
            LOWER(u.first_name) LIKE LOWER('%' || $1 || '%') OR
            LOWER(u.last_name) LIKE LOWER('%' || $1 || '%')
          )
      )
      SELECT *
      FROM matching_users
      ORDER BY relevance_score DESC, first_name ASC
      LIMIT $5;
    `;
    
    return this.database.query(query, [
      searchQuery, userLng, userLat, radiusKm, limit
    ]);
  }
}
```

### Database Connection Pooling

#### Connection Pool Configuration
```typescript
import { Pool } from 'pg';

const dbConfig = {
  // Connection pool settings
  max: 20,                    // Maximum connections in pool
  min: 5,                     // Minimum connections in pool
  idleTimeoutMillis: 30000,   // Close idle connections after 30s
  connectionTimeoutMillis: 2000, // Connection timeout
  
  // Health check
  allowExitOnIdle: false,
  
  // Connection validation
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false,
  
  // Query timeout
  query_timeout: 30000,
  
  // Keep alive
  keepAlive: true,
  keepAliveInitialDelayMillis: 10000
};

class DatabaseManager {
  private pool: Pool;
  private readReplicas: Pool[];
  
  constructor() {
    // Primary database pool
    this.pool = new Pool({
      ...dbConfig,
      host: process.env.DB_HOST,
      database: process.env.DB_NAME,
      user: process.env.DB_USER,
      password: process.env.DB_PASSWORD
    });
    
    // Read replica pools
    this.readReplicas = (process.env.DB_READ_REPLICAS || '').split(',')
      .filter(Boolean)
      .map(host => new Pool({
        ...dbConfig,
        host,
        database: process.env.DB_NAME,
        user: process.env.DB_READ_USER,
        password: process.env.DB_READ_PASSWORD
      }));
  }
  
  // Route read queries to replicas
  async query(sql: string, params?: any[], readOnly: boolean = false) {
    const pool = readOnly && this.readReplicas.length > 0
      ? this.getRandomReplica()
      : this.pool;
      
    const start = Date.now();
    try {
      const result = await pool.query(sql, params);
      const duration = Date.now() - start;
      
      // Log slow queries
      if (duration > 1000) {
        console.warn('Slow query detected:', {
          sql: sql.substring(0, 100),
          duration,
          readOnly
        });
      }
      
      return result;
    } catch (error) {
      console.error('Database query error:', {
        error: error.message,
        sql: sql.substring(0, 100),
        duration: Date.now() - start
      });
      throw error;
    }
  }
  
  private getRandomReplica(): Pool {
    const index = Math.floor(Math.random() * this.readReplicas.length);
    return this.readReplicas[index];
  }
}
```

## Caching Strategy

### Multi-Level Caching Architecture

#### Redis Configuration
```typescript
import Redis from 'ioredis';

const redisConfig = {
  // Connection settings
  host: process.env.REDIS_HOST,
  port: parseInt(process.env.REDIS_PORT || '6379'),
  password: process.env.REDIS_PASSWORD,
  
  // Connection pool
  maxRetriesPerRequest: 3,
  retryDelayOnFailover: 100,
  connectTimeout: 10000,
  commandTimeout: 5000,
  
  // Cluster configuration for production
  enableOfflineQueue: false,
  lazyConnect: true,
  
  // Keep alive
  keepAlive: 30000,
  
  // Compression
  compression: 'gzip'
};

class CacheManager {
  private redis: Redis;
  private localCache: Map<string, { value: any; expires: number }>;
  
  constructor() {
    this.redis = new Redis(redisConfig);
    this.localCache = new Map();
    
    // Clean up local cache every 5 minutes
    setInterval(() => this.cleanupLocalCache(), 5 * 60 * 1000);
  }
  
  async get(key: string, useLocalCache: boolean = true): Promise<any> {
    // L1 Cache: Local memory (fastest)
    if (useLocalCache) {
      const localEntry = this.localCache.get(key);
      if (localEntry && localEntry.expires > Date.now()) {
        return localEntry.value;
      }
    }
    
    // L2 Cache: Redis (fast)
    try {
      const redisValue = await this.redis.get(key);
      if (redisValue) {
        const parsed = JSON.parse(redisValue);
        
        // Store in local cache for 30 seconds
        if (useLocalCache) {
          this.localCache.set(key, {
            value: parsed,
            expires: Date.now() + 30000
          });
        }
        
        return parsed;
      }
    } catch (error) {
      console.error('Redis get error:', error);
    }
    
    return null;
  }
  
  async set(
    key: string, 
    value: any, 
    ttlSeconds: number = 3600,
    useLocalCache: boolean = true
  ): Promise<void> {
    const serialized = JSON.stringify(value);
    
    // Set in Redis
    try {
      await this.redis.setex(key, ttlSeconds, serialized);
    } catch (error) {
      console.error('Redis set error:', error);
    }
    
    // Set in local cache
    if (useLocalCache) {
      this.localCache.set(key, {
        value,
        expires: Date.now() + Math.min(ttlSeconds * 1000, 30000)
      });
    }
  }
  
  private cleanupLocalCache(): void {
    const now = Date.now();
    for (const [key, entry] of this.localCache.entries()) {
      if (entry.expires <= now) {
        this.localCache.delete(key);
      }
    }
  }
}
```

#### Cache Key Strategies
```typescript
class CacheKeyManager {
  static readonly PREFIXES = {
    USER_PROFILE: 'user:profile',
    USER_PERMISSIONS: 'user:permissions',
    NEIGHBORHOOD_FEED: 'neighborhood:feed',
    POST_DETAILS: 'post:details',
    MARKETPLACE_SEARCH: 'marketplace:search',
    EVENT_DETAILS: 'event:details',
    USER_CONVERSATIONS: 'user:conversations',
    NEWS_ARTICLES: 'news:articles'
  } as const;
  
  static userProfile(userId: string): string {
    return `${this.PREFIXES.USER_PROFILE}:${userId}`;
  }
  
  static userPermissions(userId: string): string {
    return `${this.PREFIXES.USER_PERMISSIONS}:${userId}`;
  }
  
  static neighborhoodFeed(
    neighborhoodId: string, 
    page: number, 
    filters?: Record<string, any>
  ): string {
    const filterHash = filters ? 
      crypto.createHash('md5').update(JSON.stringify(filters)).digest('hex') : 
      'default';
    return `${this.PREFIXES.NEIGHBORHOOD_FEED}:${neighborhoodId}:${page}:${filterHash}`;
  }
  
  static marketplaceSearch(
    location: { lat: number; lng: number },
    filters: Record<string, any>,
    page: number
  ): string {
    const locationKey = `${location.lat.toFixed(3)},${location.lng.toFixed(3)}`;
    const filterHash = crypto.createHash('md5')
      .update(JSON.stringify(filters))
      .digest('hex');
    return `${this.PREFIXES.MARKETPLACE_SEARCH}:${locationKey}:${filterHash}:${page}`;
  }
}
```

#### Smart Cache Invalidation
```typescript
class CacheInvalidationManager {
  private cacheManager: CacheManager;
  
  constructor(cacheManager: CacheManager) {
    this.cacheManager = cacheManager;
  }
  
  async invalidateUserCaches(userId: string): Promise<void> {
    const patterns = [
      CacheKeyManager.userProfile(userId),
      CacheKeyManager.userPermissions(userId),
      `${CacheKeyManager.PREFIXES.USER_CONVERSATIONS}:${userId}:*`,
      `${CacheKeyManager.PREFIXES.NEIGHBORHOOD_FEED}:*` // User might affect feeds
    ];
    
    await this.invalidateByPatterns(patterns);
  }
  
  async invalidatePostCaches(postId: string, neighborhoodId: string): Promise<void> {
    const patterns = [
      `${CacheKeyManager.PREFIXES.POST_DETAILS}:${postId}`,
      `${CacheKeyManager.PREFIXES.NEIGHBORHOOD_FEED}:${neighborhoodId}:*`
    ];
    
    await this.invalidateByPatterns(patterns);
  }
  
  async invalidateNeighborhoodCaches(neighborhoodId: string): Promise<void> {
    const patterns = [
      `${CacheKeyManager.PREFIXES.NEIGHBORHOOD_FEED}:${neighborhoodId}:*`,
      `neighborhood:stats:${neighborhoodId}`,
      `neighborhood:members:${neighborhoodId}:*`
    ];
    
    await this.invalidateByPatterns(patterns);
  }
  
  private async invalidateByPatterns(patterns: string[]): Promise<void> {
    for (const pattern of patterns) {
      if (pattern.includes('*')) {
        // Use Redis SCAN for pattern matching
        const keys = await this.scanKeys(pattern);
        if (keys.length > 0) {
          await this.cacheManager.del(...keys);
        }
      } else {
        await this.cacheManager.del(pattern);
      }
    }
  }
  
  private async scanKeys(pattern: string): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';
    
    do {
      const result = await this.cacheManager.redis.scan(
        cursor, 'MATCH', pattern, 'COUNT', 100
      );
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');
    
    return keys;
  }
}
```

## API Performance Optimization

### Response Optimization

#### Compression and Serialization
```typescript
import compression from 'compression';
import { Transform } from 'stream';

class ResponseOptimizer {
  static setupCompression() {
    return compression({
      filter: (req, res) => {
        // Don't compress responses if the client doesn't support it
        if (req.headers['x-no-compression']) {
          return false;
        }
        
        // Use compression for JSON responses
        return compression.filter(req, res);
      },
      
      // Compression level (1-9, 6 is default)
      level: 6,
      
      // Minimum response size to compress
      threshold: 1024,
      
      // Compression algorithm preference
      // (gzip is widely supported, brotli is more efficient)
      strategy: compression.constants.Z_DEFAULT_STRATEGY
    });
  }
  
  static optimizeJSON(data: any): any {
    // Remove null values to reduce payload size
    return this.removeNulls(data);
  }
  
  private static removeNulls(obj: any): any {
    if (Array.isArray(obj)) {
      return obj.map(item => this.removeNulls(item));
    } else if (obj !== null && typeof obj === 'object') {
      const result: any = {};
      for (const [key, value] of Object.entries(obj)) {
        if (value !== null && value !== undefined) {
          result[key] = this.removeNulls(value);
        }
      }
      return result;
    }
    return obj;
  }
  
  // Streaming JSON for large responses
  static createJSONStream(data: any[]): Transform {
    let first = true;
    
    return new Transform({
      objectMode: true,
      transform(chunk, encoding, callback) {
        const prefix = first ? '[' : ',';
        first = false;
        this.push(prefix + JSON.stringify(chunk));
        callback();
      },
      flush(callback) {
        this.push(first ? '[]' : ']');
        callback();
      }
    });
  }
}
```

#### Field Selection and Pagination
```typescript
interface QueryOptions {
  fields?: string[];
  page?: number;
  limit?: number;
  cursor?: string;
  sort?: string;
  filters?: Record<string, any>;
}

class QueryOptimizer {
  static parseFields(fieldsParam?: string): string[] | undefined {
    if (!fieldsParam) return undefined;
    
    return fieldsParam.split(',')
      .map(field => field.trim())
      .filter(field => /^[a-zA-Z0-9_\.]+$/.test(field)); // Security: only allow safe field names
  }
  
  static buildSelectClause(
    baseFields: string[], 
    requestedFields?: string[]
  ): string[] {
    if (!requestedFields) return baseFields;
    
    // Always include essential fields
    const essentialFields = ['id', 'created_at'];
    const allowedFields = [...essentialFields, ...baseFields];
    
    return requestedFields.filter(field => 
      allowedFields.includes(field)
    );
  }
  
  static async paginateQuery<T>(
    query: any,
    options: QueryOptions
  ): Promise<{
    data: T[];
    pagination: {
      current_page: number;
      total_pages: number;
      total_items: number;
      items_per_page: number;
      has_next: boolean;
      has_previous: boolean;
    };
  }> {
    const limit = Math.min(options.limit || 20, 100); // Max 100 items per page
    const page = Math.max(options.page || 1, 1);
    const offset = (page - 1) * limit;
    
    // Get total count (cache this for expensive queries)
    const totalItems = await query.clone().count();
    const totalPages = Math.ceil(totalItems / limit);
    
    // Get paginated data
    const data = await query
      .limit(limit)
      .offset(offset);
    
    return {
      data,
      pagination: {
        current_page: page,
        total_pages: totalPages,
        total_items: totalItems,
        items_per_page: limit,
        has_next: page < totalPages,
        has_previous: page > 1
      }
    };
  }
  
  // Cursor-based pagination for real-time feeds
  static async cursorPaginate<T>(
    query: any,
    options: { 
      cursor?: string; 
      limit?: number; 
      cursorField?: string;
    }
  ): Promise<{
    data: T[];
    pagination: {
      next_cursor?: string;
      has_more: boolean;
    };
  }> {
    const limit = Math.min(options.limit || 20, 100);
    const cursorField = options.cursorField || 'created_at';
    
    let modifiedQuery = query.orderBy(cursorField, 'desc').limit(limit + 1);
    
    if (options.cursor) {
      const cursorValue = Buffer.from(options.cursor, 'base64').toString();
      modifiedQuery = modifiedQuery.where(cursorField, '<', cursorValue);
    }
    
    const results = await modifiedQuery;
    const hasMore = results.length > limit;
    const data = hasMore ? results.slice(0, limit) : results;
    
    let nextCursor: string | undefined;
    if (hasMore && data.length > 0) {
      const lastItem = data[data.length - 1];
      nextCursor = Buffer.from(lastItem[cursorField].toISOString()).toString('base64');
    }
    
    return {
      data,
      pagination: {
        next_cursor: nextCursor,
        has_more: hasMore
      }
    };
  }
}
```

## Nigerian Network Optimization

### Data-Light Mode Implementation
```typescript
interface DataLightConfig {
  maxImageSize: number;
  maxVideoSize: number;
  imageQuality: number;
  enableVideoStreaming: boolean;
  useTextOnlyMode: boolean;
  reducedAnimations: boolean;
}

class NigerianNetworkOptimizer {
  private config: DataLightConfig;
  
  constructor(userPreferences: any) {
    this.config = {
      maxImageSize: userPreferences.dataLightMode ? 100 * 1024 : 2 * 1024 * 1024, // 100KB vs 2MB
      maxVideoSize: userPreferences.dataLightMode ? 500 * 1024 : 10 * 1024 * 1024, // 500KB vs 10MB
      imageQuality: userPreferences.dataLightMode ? 60 : 85,
      enableVideoStreaming: !userPreferences.dataLightMode,
      useTextOnlyMode: userPreferences.textOnlyMode || false,
      reducedAnimations: userPreferences.dataLightMode || false
    };
  }
  
  async optimizeImageResponse(imageUrl: string): Promise<string> {
    if (this.config.useTextOnlyMode) {
      return ''; // Return empty string for text-only mode
    }
    
    // Generate optimized image URL with CloudFlare transformations
    const params = new URLSearchParams({
      quality: this.config.imageQuality.toString(),
      format: 'auto', // WebP for supported browsers, JPEG fallback
      fit: 'scale-down',
      width: this.config.maxImageSize < 500 * 1024 ? '400' : '800'
    });
    
    return `${imageUrl}?${params.toString()}`;
  }
  
  async optimizeAPIResponse(data: any, endpoint: string): Promise<any> {
    if (this.config.useTextOnlyMode) {
      return this.stripMediaFromResponse(data);
    }
    
    // Reduce response size for slow connections
    if (this.config.maxImageSize < 500 * 1024) {
      return this.createLightweightResponse(data, endpoint);
    }
    
    return data;
  }
  
  private stripMediaFromResponse(data: any): any {
    if (Array.isArray(data)) {
      return data.map(item => this.stripMediaFromResponse(item));
    }
    
    if (data && typeof data === 'object') {
      const result = { ...data };
      
      // Remove media fields
      delete result.profile_picture_url;
      delete result.cover_image_url;
      delete result.media;
      delete result.thumbnail_url;
      
      // Recursively process nested objects
      for (const key in result) {
        if (result[key] && typeof result[key] === 'object') {
          result[key] = this.stripMediaFromResponse(result[key]);
        }
      }
      
      return result;
    }
    
    return data;
  }
  
  private createLightweightResponse(data: any, endpoint: string): any {
    switch (endpoint) {
      case 'feed':
        return this.optimizeFeedResponse(data);
      case 'marketplace':
        return this.optimizeMarketplaceResponse(data);
      case 'events':
        return this.optimizeEventsResponse(data);
      default:
        return data;
    }
  }
  
  private optimizeFeedResponse(data: any): any {
    if (!data.posts) return data;
    
    return {
      ...data,
      posts: data.posts.map((post: any) => ({
        id: post.id,
        title: post.title,
        content: post.content.substring(0, 200), // Truncate content
        author: {
          id: post.author.id,
          first_name: post.author.first_name,
          last_name: post.author.last_name
          // Remove profile_picture_url
        },
        category: post.category,
        reactions_count: post.reactions_count,
        comments_count: post.comments_count,
        created_at: post.created_at,
        has_media: post.media && post.media.length > 0
        // Remove actual media array
      }))
    };
  }
}
```

### Adaptive Content Delivery
```typescript
class AdaptiveContentDelivery {
  private userConnectionInfo: {
    type: 'slow' | 'fast';
    bandwidth: number;
    latency: number;
  };
  
  constructor(userAgent: string, headers: Record<string, string>) {
    this.userConnectionInfo = this.detectConnectionQuality(userAgent, headers);
  }
  
  private detectConnectionQuality(userAgent: string, headers: Record<string, string>) {
    // Detect connection type from headers and user agent
    const connectionHeader = headers['connection'];
    const saveDataHeader = headers['save-data']; // Chrome data saver
    
    // Simplified connection detection
    if (saveDataHeader === 'on' || userAgent.includes('Opera Mini')) {
      return { type: 'slow' as const, bandwidth: 100, latency: 500 };
    }
    
    // Default to fast connection
    return { type: 'fast' as const, bandwidth: 1000, latency: 50 };
  }
  
  async adaptContent(content: any, contentType: string): Promise<any> {
    if (this.userConnectionInfo.type === 'slow') {
      return this.optimizeForSlowConnection(content, contentType);
    }
    
    return content;
  }
  
  private async optimizeForSlowConnection(content: any, contentType: string): Promise<any> {
    switch (contentType) {
      case 'feed':
        return {
          ...content,
          posts: content.posts?.slice(0, 10), // Reduce items
          pagination: {
            ...content.pagination,
            items_per_page: 10
          }
        };
        
      case 'marketplace':
        return {
          ...content,
          listings: content.listings?.map((listing: any) => ({
            ...listing,
            description: listing.description?.substring(0, 100),
            media: listing.media?.slice(0, 1) // Only first image
          }))
        };
        
      default:
        return content;
    }
  }
}
```

## Performance Monitoring

### Metrics Collection
```typescript
interface PerformanceMetrics {
  endpoint: string;
  method: string;
  responseTime: number;
  statusCode: number;
  userId?: string;
  userAgent: string;
  ipAddress: string;
  timestamp: Date;
  memoryUsage: NodeJS.MemoryUsage;
  cpuUsage?: NodeJS.CpuUsage;
}

class PerformanceMonitor {
  private metrics: PerformanceMetrics[] = [];
  
  middleware() {
    return (req: Request, res: Response, next: NextFunction) => {
      const startTime = process.hrtime.bigint();
      const startCpuUsage = process.cpuUsage();
      
      res.on('finish', () => {
        const endTime = process.hrtime.bigint();
        const responseTime = Number(endTime - startTime) / 1000000; // Convert to milliseconds
        
        const metric: PerformanceMetrics = {
          endpoint: req.route?.path || req.path,
          method: req.method,
          responseTime,
          statusCode: res.statusCode,
          userId: req.auth?.userId,
          userAgent: req.get('User-Agent') || '',
          ipAddress: req.ip,
          timestamp: new Date(),
          memoryUsage: process.memoryUsage(),
          cpuUsage: process.cpuUsage(startCpuUsage)
        };
        
        this.collectMetric(metric);
      });
      
      next();
    };
  }
  
  private async collectMetric(metric: PerformanceMetrics): Promise<void> {
    // Log slow requests
    if (metric.responseTime > 1000) {
      console.warn('Slow request detected:', {
        endpoint: metric.endpoint,
        method: metric.method,
        responseTime: metric.responseTime,
        userId: metric.userId
      });
    }
    
    // Store metrics (in production, send to monitoring service)
    this.metrics.push(metric);
    
    // Keep only last 1000 metrics in memory
    if (this.metrics.length > 1000) {
      this.metrics = this.metrics.slice(-1000);
    }
    
    // Send to external monitoring service
    await this.sendToMonitoringService(metric);
  }
  
  private async sendToMonitoringService(metric: PerformanceMetrics): Promise<void> {
    // Implementation depends on monitoring service (DataDog, New Relic, etc.)
    try {
      // Example: DataDog StatsD
      // statsd.histogram('api.response_time', metric.responseTime, {
      //   endpoint: metric.endpoint,
      //   method: metric.method,
      //   status_code: metric.statusCode.toString()
      // });
    } catch (error) {
      console.error('Failed to send metric to monitoring service:', error);
    }
  }
  
  getMetricsSummary() {
    const recentMetrics = this.metrics.slice(-100);
    
    return {
      avg_response_time: recentMetrics.reduce((sum, m) => sum + m.responseTime, 0) / recentMetrics.length,
      p95_response_time: this.calculatePercentile(recentMetrics.map(m => m.responseTime), 95),
      error_rate: recentMetrics.filter(m => m.statusCode >= 400).length / recentMetrics.length,
      total_requests: recentMetrics.length,
      memory_usage: process.memoryUsage(),
      timestamp: new Date()
    };
  }
  
  private calculatePercentile(values: number[], percentile: number): number {
    const sorted = values.sort((a, b) => a - b);
    const index = Math.ceil(sorted.length * (percentile / 100)) - 1;
    return sorted[index] || 0;
  }
}
```

This comprehensive performance optimization strategy ensures HoodMe can handle high traffic loads while providing excellent user experience even on slower Nigerian network connections.