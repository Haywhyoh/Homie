# HoodMe Security Implementation

## Overview
This document outlines the comprehensive security implementation for HoodMe, covering authentication, data protection, API security, and compliance with Nigerian Data Protection Regulation (NDPR).

## Authentication & Authorization

### JWT Implementation

#### Token Structure
```typescript
interface JWTPayload {
  userId: string;
  email: string;
  phoneNumber: string;
  neighborhoods: string[];
  roles: string[];
  permissions: string[];
  sessionId: string;
  iat: number; // Issued at
  exp: number; // Expires at
  iss: string; // Issuer
  aud: string; // Audience
}
```

#### Token Configuration
```typescript
const jwtConfig = {
  algorithm: 'RS256', // RSA with SHA-256
  issuer: 'HoodMe.com',
  audience: 'HoodMe-api',
  accessTokenExpiry: '15m',
  refreshTokenExpiry: '30d',
  keyRotationInterval: '90d'
};
```

#### Key Management
```typescript
// RSA Key Pair Generation
const generateKeyPair = async () => {
  const { publicKey, privateKey } = await crypto.generateKeyPair('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem'
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem'
    }
  });
  
  return { publicKey, privateKey };
};

// Store keys in AWS Secrets Manager / Azure Key Vault
const storeKeys = async (publicKey: string, privateKey: string) => {
  await secretsManager.createSecret({
    Name: 'HoodMe/jwt/private-key',
    SecretString: privateKey
  });
  
  await secretsManager.createSecret({
    Name: 'HoodMe/jwt/public-key',
    SecretString: publicKey
  });
};
```

### Role-Based Access Control (RBAC)

#### User Roles
```typescript
enum UserRoles {
  USER = 'user',
  VERIFIED_USER = 'verified_user',
  NEIGHBORHOOD_ADMIN = 'neighborhood_admin',
  CONTENT_MODERATOR = 'content_moderator',
  SUPER_ADMIN = 'super_admin'
}

enum Permissions {
  // Post permissions
  READ_POSTS = 'read:posts',
  CREATE_POSTS = 'create:posts',
  EDIT_OWN_POSTS = 'edit:own_posts',
  DELETE_OWN_POSTS = 'delete:own_posts',
  
  // Moderation permissions
  MODERATE_CONTENT = 'moderate:content',
  BAN_USERS = 'ban:users',
  VERIFY_ALERTS = 'verify:alerts',
  
  // Admin permissions
  MANAGE_USERS = 'manage:users',
  MANAGE_NEIGHBORHOODS = 'manage:neighborhoods',
  ACCESS_ANALYTICS = 'access:analytics',
  
  // System permissions
  SYSTEM_ADMIN = 'system:admin'
}
```

#### Permission Matrix
```typescript
const rolePermissions: Record<UserRoles, Permissions[]> = {
  [UserRoles.USER]: [
    Permissions.READ_POSTS,
    Permissions.CREATE_POSTS,
    Permissions.EDIT_OWN_POSTS,
    Permissions.DELETE_OWN_POSTS
  ],
  
  [UserRoles.VERIFIED_USER]: [
    ...rolePermissions[UserRoles.USER],
    Permissions.VERIFY_ALERTS
  ],
  
  [UserRoles.NEIGHBORHOOD_ADMIN]: [
    ...rolePermissions[UserRoles.VERIFIED_USER],
    Permissions.MODERATE_CONTENT,
    Permissions.MANAGE_NEIGHBORHOOD_USERS
  ],
  
  [UserRoles.CONTENT_MODERATOR]: [
    ...rolePermissions[UserRoles.VERIFIED_USER],
    Permissions.MODERATE_CONTENT,
    Permissions.BAN_USERS
  ],
  
  [UserRoles.SUPER_ADMIN]: [
    ...Object.values(Permissions)
  ]
};
```

#### Authorization Middleware
```typescript
interface AuthContext {
  userId: string;
  roles: UserRoles[];
  permissions: Permissions[];
  neighborhoods: string[];
}

const authorize = (requiredPermissions: Permissions[]) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const token = extractTokenFromHeader(req.headers.authorization);
      const payload = await verifyJWT(token);
      
      const userPermissions = await getUserPermissions(payload.userId);
      
      const hasPermission = requiredPermissions.every(permission =>
        userPermissions.includes(permission)
      );
      
      if (!hasPermission) {
        return res.status(403).json({
          success: false,
          error: {
            code: 'INSUFFICIENT_PERMISSIONS',
            message: 'You do not have permission to perform this action'
          }
        });
      }
      
      req.auth = {
        userId: payload.userId,
        roles: payload.roles,
        permissions: userPermissions,
        neighborhoods: payload.neighborhoods
      };
      
      next();
    } catch (error) {
      return res.status(401).json({
        success: false,
        error: {
          code: 'INVALID_TOKEN',
          message: 'Invalid or expired token'
        }
      });
    }
  };
};

// Usage example
app.post('/api/v1/posts', 
  authorize([Permissions.CREATE_POSTS]),
  createPostHandler
);
```

## Data Encryption

### Encryption at Rest

#### Database Encryption
```typescript
interface EncryptionConfig {
  algorithm: 'aes-256-gcm';
  keyDerivation: 'pbkdf2';
  iterations: 100000;
  saltLength: 32;
  ivLength: 16;
  tagLength: 16;
}

class DataEncryption {
  private masterKey: Buffer;
  
  constructor(masterKey: string) {
    this.masterKey = Buffer.from(masterKey, 'hex');
  }
  
  async encrypt(data: string, context?: string): Promise<string> {
    const salt = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);
    
    // Derive key using PBKDF2
    const key = crypto.pbkdf2Sync(this.masterKey, salt, 100000, 32, 'sha256');
    
    const cipher = crypto.createCipher('aes-256-gcm', key, iv);
    
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    
    const tag = cipher.getAuthTag();
    
    // Combine salt + iv + tag + encrypted data
    const result = salt.toString('hex') + 
                   iv.toString('hex') + 
                   tag.toString('hex') + 
                   encrypted;
    
    return result;
  }
  
  async decrypt(encryptedData: string): Promise<string> {
    const salt = Buffer.from(encryptedData.substr(0, 64), 'hex');
    const iv = Buffer.from(encryptedData.substr(64, 32), 'hex');
    const tag = Buffer.from(encryptedData.substr(96, 32), 'hex');
    const encrypted = encryptedData.substr(128);
    
    const key = crypto.pbkdf2Sync(this.masterKey, salt, 100000, 32, 'sha256');
    
    const decipher = crypto.createDecipher('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  }
}
```

#### PII Encryption
```typescript
interface PIIField {
  field: string;
  encryptionLevel: 'standard' | 'high';
  searchable: boolean;
}

const piiFields: PIIField[] = [
  { field: 'phone_number', encryptionLevel: 'high', searchable: true },
  { field: 'email', encryptionLevel: 'standard', searchable: true },
  { field: 'date_of_birth', encryptionLevel: 'high', searchable: false },
  { field: 'national_id', encryptionLevel: 'high', searchable: false }
];

// Searchable encryption for phone numbers and emails
class SearchableEncryption {
  async createSearchableHash(value: string): Promise<string> {
    // Create a hash that allows for searching while maintaining privacy
    const normalized = this.normalizeValue(value);
    return crypto.createHash('sha256')
      .update(normalized + process.env.SEARCH_SALT)
      .digest('hex');
  }
  
  private normalizeValue(value: string): string {
    if (value.includes('@')) {
      // Email normalization
      return value.toLowerCase().trim();
    } else {
      // Phone number normalization
      return value.replace(/\D/g, ''); // Remove non-digits
    }
  }
}
```

### Encryption in Transit

#### TLS Configuration
```typescript
const tlsOptions = {
  // TLS 1.3 minimum
  secureProtocol: 'TLSv1_3_method',
  
  // Strong cipher suites
  ciphers: [
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'TLS_AES_128_GCM_SHA256'
  ].join(':'),
  
  // HSTS settings
  headers: {
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  }
};
```

## API Security

### Input Validation & Sanitization

#### Validation Schemas
```typescript
import Joi from 'joi';

const userRegistrationSchema = Joi.object({
  phone_number: Joi.string()
    .pattern(/^\+234[789][01]\d{8}$/)
    .required()
    .messages({
      'string.pattern.base': 'Phone number must be a valid Nigerian number'
    }),
  
  email: Joi.string()
    .email()
    .required(),
  
  first_name: Joi.string()
    .min(2)
    .max(50)
    .pattern(/^[a-zA-Z\s\-']+$/)
    .required(),
  
  last_name: Joi.string()
    .min(2)
    .max(50)
    .pattern(/^[a-zA-Z\s\-']+$/)
    .required(),
  
  password: Joi.string()
    .min(8)
    .max(128)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    })
});

// Content validation for posts
const postContentSchema = Joi.object({
  title: Joi.string()
    .max(200)
    .pattern(/^[^<>\"'&]*$/) // Prevent HTML injection
    .required(),
  
  content: Joi.string()
    .max(5000)
    .custom((value, helpers) => {
      // Custom sanitization
      const sanitized = sanitizeHtml(value, {
        allowedTags: [], // No HTML tags allowed
        allowedAttributes: {}
      });
      return sanitized;
    })
    .required()
});
```

#### SQL Injection Prevention
```typescript
// Using parameterized queries with TypeORM
class UserRepository {
  async findByEmail(email: string): Promise<User | null> {
    return this.repository
      .createQueryBuilder('user')
      .where('user.email = :email', { email }) // Parameterized query
      .getOne();
  }
  
  async searchUsers(query: string, neighborhoodId: string): Promise<User[]> {
    // Use TypeORM's query builder for complex queries
    return this.repository
      .createQueryBuilder('user')
      .innerJoin('user.neighborhoods', 'neighborhood')
      .where('neighborhood.id = :neighborhoodId', { neighborhoodId })
      .andWhere(
        new Brackets(qb => {
          qb.where('LOWER(user.first_name) LIKE LOWER(:query)', { query: `%${query}%` })
            .orWhere('LOWER(user.last_name) LIKE LOWER(:query)', { query: `%${query}%` });
        })
      )
      .getMany();
  }
}
```

### Rate Limiting

#### Tiered Rate Limiting
```typescript
interface RateLimitConfig {
  windowMs: number;
  max: number;
  message: string;
  standardHeaders: boolean;
  legacyHeaders: boolean;
  keyGenerator: (req: Request) => string;
}

const rateLimitConfigs: Record<string, RateLimitConfig> = {
  // Authentication endpoints
  auth: {
    windowMs: 60 * 1000, // 1 minute
    max: 10,
    message: 'Too many authentication attempts, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.ip
  },
  
  // General API endpoints
  api: {
    windowMs: 60 * 1000, // 1 minute
    max: 100,
    message: 'Too many requests, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.auth?.userId || req.ip
  },
  
  // File upload endpoints
  upload: {
    windowMs: 60 * 1000, // 1 minute
    max: 20,
    message: 'Too many file uploads, please try again later',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.auth?.userId || req.ip
  },
  
  // Messaging endpoints
  messaging: {
    windowMs: 60 * 1000, // 1 minute
    max: 200,
    message: 'Too many messages, please slow down',
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => req.auth?.userId || req.ip
  }
};

// Advanced rate limiting with Redis
class AdvancedRateLimit {
  private redis: Redis;
  
  constructor(redis: Redis) {
    this.redis = redis;
  }
  
  async checkLimit(
    key: string, 
    limit: number, 
    windowSeconds: number
  ): Promise<{ allowed: boolean; remaining: number; resetTime: number }> {
    const now = Date.now();
    const windowStart = now - (windowSeconds * 1000);
    
    // Remove old entries and count current requests
    await this.redis.zremrangebyscore(key, 0, windowStart);
    const currentCount = await this.redis.zcard(key);
    
    if (currentCount >= limit) {
      const resetTime = await this.redis.zrange(key, 0, 0, 'WITHSCORES');
      return {
        allowed: false,
        remaining: 0,
        resetTime: parseInt(resetTime[1]) + (windowSeconds * 1000)
      };
    }
    
    // Add current request
    await this.redis.zadd(key, now, `${now}-${Math.random()}`);
    await this.redis.expire(key, windowSeconds);
    
    return {
      allowed: true,
      remaining: limit - currentCount - 1,
      resetTime: now + (windowSeconds * 1000)
    };
  }
}
```

## Content Security & Moderation

### Automated Content Filtering
```typescript
interface ContentModerationResult {
  isAllowed: boolean;
  confidence: number;
  flags: string[];
  requiresHumanReview: boolean;
}

class ContentModerationService {
  private profanityFilter: any;
  private mlClassifier: any;
  
  async moderateContent(content: string, contentType: string): Promise<ContentModerationResult> {
    const results = await Promise.all([
      this.checkProfanity(content),
      this.checkSpam(content),
      this.checkPersonalInfo(content),
      this.checkMlClassification(content, contentType)
    ]);
    
    const flags = results.flatMap(r => r.flags);
    const highestRisk = Math.max(...results.map(r => r.riskScore));
    
    return {
      isAllowed: highestRisk < 0.7,
      confidence: 1 - highestRisk,
      flags,
      requiresHumanReview: highestRisk >= 0.5 && highestRisk < 0.7
    };
  }
  
  private async checkProfanity(content: string) {
    const profanityWords = await this.getProfanityList();
    const words = content.toLowerCase().split(/\s+/);
    const matches = words.filter(word => profanityWords.includes(word));
    
    return {
      flags: matches.length > 0 ? ['profanity'] : [],
      riskScore: Math.min(matches.length * 0.3, 1.0)
    };
  }
  
  private async checkPersonalInfo(content: string) {
    const patterns = {
      phone: /(\+234|0)[789][01]\d{8}/g,
      email: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
      account: /\b\d{10,}\b/g
    };
    
    const flags = [];
    let riskScore = 0;
    
    for (const [type, pattern] of Object.entries(patterns)) {
      if (pattern.test(content)) {
        flags.push(`personal_info_${type}`);
        riskScore += 0.4;
      }
    }
    
    return { flags, riskScore: Math.min(riskScore, 1.0) };
  }
}
```

### Image Content Moderation
```typescript
class ImageModerationService {
  async moderateImage(imageUrl: string): Promise<ContentModerationResult> {
    const results = await Promise.all([
      this.checkNSFWContent(imageUrl),
      this.checkViolentContent(imageUrl),
      this.checkTextInImage(imageUrl)
    ]);
    
    const highestRisk = Math.max(...results.map(r => r.riskScore));
    const flags = results.flatMap(r => r.flags);
    
    return {
      isAllowed: highestRisk < 0.8,
      confidence: 1 - highestRisk,
      flags,
      requiresHumanReview: highestRisk >= 0.6 && highestRisk < 0.8
    };
  }
  
  private async checkNSFWContent(imageUrl: string) {
    // Integration with AWS Rekognition or Google Vision API
    const response = await this.visionAPI.detectUnsafeContent(imageUrl);
    
    return {
      flags: response.adult > 0.7 ? ['nsfw'] : [],
      riskScore: response.adult
    };
  }
}
```

## NDPR Compliance

### Data Subject Rights Implementation
```typescript
interface DataSubjectRequest {
  type: 'access' | 'rectification' | 'erasure' | 'portability' | 'restriction';
  userId: string;
  requestDate: Date;
  completionDeadline: Date;
  status: 'pending' | 'in_progress' | 'completed' | 'rejected';
}

class NDPRComplianceService {
  async handleDataSubjectRequest(request: DataSubjectRequest): Promise<void> {
    switch (request.type) {
      case 'access':
        await this.handleDataAccessRequest(request);
        break;
      case 'erasure':
        await this.handleDataErasureRequest(request);
        break;
      case 'portability':
        await this.handleDataPortabilityRequest(request);
        break;
      // ... other cases
    }
  }
  
  private async handleDataErasureRequest(request: DataSubjectRequest): Promise<void> {
    const userId = request.userId;
    
    // Anonymize rather than delete to maintain data integrity
    await this.anonymizeUserData(userId);
    
    // Log the action for audit purposes
    await this.auditLogger.log({
      action: 'data_erasure',
      userId,
      requestId: request.id,
      timestamp: new Date(),
      method: 'anonymization'
    });
  }
  
  private async anonymizeUserData(userId: string): Promise<void> {
    const anonymousId = `anon_${crypto.randomUUID()}`;
    
    await this.database.transaction(async (trx) => {
      // Update user record
      await trx('users')
        .where('id', userId)
        .update({
          first_name: 'Anonymous',
          last_name: 'User',
          email: `${anonymousId}@deleted.local`,
          phone_number: null,
          profile_picture_url: null,
          date_of_birth: null,
          is_active: false,
          anonymized_at: new Date()
        });
      
      // Update related records
      await trx('posts')
        .where('user_id', userId)
        .update({ user_id: null, anonymized: true });
        
      await trx('messages')
        .where('sender_id', userId)
        .update({ sender_id: null, anonymized: true });
    });
  }
  
  async generateDataPortabilityExport(userId: string): Promise<string> {
    const userData = await this.gatherUserData(userId);
    
    const exportData = {
      export_date: new Date().toISOString(),
      user_id: userId,
      profile: userData.profile,
      posts: userData.posts,
      messages: userData.messages,
      events: userData.events,
      marketplace_listings: userData.listings,
      preferences: userData.preferences
    };
    
    // Generate downloadable file
    const fileName = `HoodMe_data_export_${userId}_${Date.now()}.json`;
    const filePath = await this.generateSecureDownloadLink(fileName, exportData);
    
    return filePath;
  }
}
```

### Consent Management
```typescript
interface ConsentRecord {
  userId: string;
  consentType: string;
  granted: boolean;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  version: string;
}

class ConsentManager {
  async recordConsent(consent: ConsentRecord): Promise<void> {
    await this.database('user_consents').insert({
      user_id: consent.userId,
      consent_type: consent.consentType,
      granted: consent.granted,
      granted_at: consent.timestamp,
      ip_address: consent.ipAddress,
      user_agent: consent.userAgent,
      privacy_policy_version: consent.version
    });
  }
  
  async checkConsent(userId: string, consentType: string): Promise<boolean> {
    const latestConsent = await this.database('user_consents')
      .where('user_id', userId)
      .where('consent_type', consentType)
      .orderBy('granted_at', 'desc')
      .first();
    
    return latestConsent?.granted || false;
  }
  
  async withdrawConsent(userId: string, consentType: string): Promise<void> {
    await this.recordConsent({
      userId,
      consentType,
      granted: false,
      timestamp: new Date(),
      ipAddress: '', // From request context
      userAgent: '', // From request context
      version: process.env.PRIVACY_POLICY_VERSION
    });
    
    // Take appropriate action based on consent type
    await this.handleConsentWithdrawal(userId, consentType);
  }
}
```

## Security Monitoring & Incident Response

### Security Event Logging
```typescript
interface SecurityEvent {
  eventType: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  userId?: string;
  ipAddress: string;
  userAgent?: string;
  details: Record<string, any>;
  timestamp: Date;
}

class SecurityLogger {
  async logSecurityEvent(event: SecurityEvent): Promise<void> {
    // Log to secure logging system
    await this.logger.security({
      ...event,
      id: crypto.randomUUID(),
      service: 'HoodMe-api'
    });
    
    // Alert on high severity events
    if (event.severity === 'high' || event.severity === 'critical') {
      await this.alertManager.sendAlert({
        title: `Security Event: ${event.eventType}`,
        severity: event.severity,
        details: event.details,
        timestamp: event.timestamp
      });
    }
  }
}

// Security event types
const SecurityEvents = {
  FAILED_LOGIN: 'failed_login',
  SUSPICIOUS_LOGIN: 'suspicious_login',
  RATE_LIMIT_EXCEEDED: 'rate_limit_exceeded',
  SQL_INJECTION_ATTEMPT: 'sql_injection_attempt',
  XSS_ATTEMPT: 'xss_attempt',
  PRIVILEGE_ESCALATION: 'privilege_escalation',
  DATA_BREACH_ATTEMPT: 'data_breach_attempt',
  MALWARE_UPLOAD: 'malware_upload'
};
```

### Intrusion Detection
```typescript
class IntrusionDetectionSystem {
  private suspiciousPatterns = [
    /union\s+select/i,
    /<script.*?>.*?<\/script>/i,
    /javascript:/i,
    /onload\s*=/i,
    /eval\s*\(/i
  ];
  
  async analyzeRequest(req: Request): Promise<boolean> {
    const risks = await Promise.all([
      this.checkSQLInjection(req.body),
      this.checkXSSAttempt(req.body),
      this.checkRateLimitAbuse(req.ip),
      this.checkGeolocationAnomaly(req.ip, req.auth?.userId)
    ]);
    
    const totalRisk = risks.reduce((sum, risk) => sum + risk, 0);
    
    if (totalRisk > 0.7) {
      await this.securityLogger.logSecurityEvent({
        eventType: SecurityEvents.DATA_BREACH_ATTEMPT,
        severity: 'high',
        userId: req.auth?.userId,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        details: {
          endpoint: req.path,
          method: req.method,
          riskScore: totalRisk
        },
        timestamp: new Date()
      });
      
      return true; // Block request
    }
    
    return false;
  }
  
  private async checkGeolocationAnomaly(ip: string, userId?: string): Promise<number> {
    if (!userId) return 0;
    
    const currentLocation = await this.geoip.lookup(ip);
    const userHistory = await this.getUserLocationHistory(userId);
    
    if (userHistory.length === 0) return 0;
    
    const isAnomalous = !userHistory.some(location => 
      this.calculateDistance(currentLocation, location) < 1000 // km
    );
    
    return isAnomalous ? 0.8 : 0;
  }
}
```

This comprehensive security implementation ensures that HoodMe meets international security standards while complying with Nigerian data protection regulations.