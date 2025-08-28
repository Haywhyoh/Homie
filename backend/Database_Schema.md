# HoodMe Database Schema

## Overview
This document contains the complete database schema for HoodMe, designed to support all features outlined in the PRD.

## Database Technology
- **Primary Database**: PostgreSQL 15+
- **Extensions**: PostGIS (for geospatial queries)
- **Caching**: Redis 7+
- **Search**: Elasticsearch 8+

## Schema Organization

### Core User & Authentication Tables

#### Users Table
```sql
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    phone_number VARCHAR(15) UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    profile_picture_url TEXT,
    date_of_birth DATE,
    gender VARCHAR(10),
    is_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    preferred_language VARCHAR(10) DEFAULT 'en',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    last_login_at TIMESTAMP
);
```

#### OTP Verifications Table
```sql
CREATE TABLE otp_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    contact_method VARCHAR(50), -- 'phone' or 'email'
    contact_value VARCHAR(255),
    otp_code VARCHAR(6),
    purpose VARCHAR(50), -- 'registration', 'login', 'password_reset'
    expires_at TIMESTAMP,
    is_used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### User Sessions Table
```sql
CREATE TABLE user_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    device_id VARCHAR(255),
    device_type VARCHAR(50),
    refresh_token_hash VARCHAR(255),
    ip_address INET,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Geolocation & Neighborhood Tables

#### States Table
```sql
CREATE TABLE states (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    code VARCHAR(10) UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Local Government Areas Table
```sql
CREATE TABLE local_government_areas (
    id SERIAL PRIMARY KEY,
    state_id INTEGER REFERENCES states(id),
    name VARCHAR(100) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Neighborhoods Table
```sql
CREATE TABLE neighborhoods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    lga_id INTEGER REFERENCES local_government_areas(id),
    boundary_coordinates JSONB, -- GeoJSON polygon
    center_latitude DECIMAL(10, 8),
    center_longitude DECIMAL(11, 8),
    radius_meters INTEGER DEFAULT 1000,
    is_verified BOOLEAN DEFAULT FALSE,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### User-Neighborhood Relationships Table
```sql
CREATE TABLE user_neighborhoods (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    relationship_type VARCHAR(20), -- 'resident', 'worker', 'visitor'
    verification_method VARCHAR(50), -- 'gps', 'referral', 'manual'
    verified_by UUID REFERENCES users(id),
    is_primary BOOLEAN DEFAULT FALSE,
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, neighborhood_id)
);
```

#### User Locations Table
```sql
CREATE TABLE user_locations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    accuracy_meters INTEGER,
    recorded_at TIMESTAMP DEFAULT NOW(),
    is_current BOOLEAN DEFAULT TRUE
);
```

### Social Feed & Content Tables

#### Post Categories Table
```sql
CREATE TABLE post_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL,
    description TEXT,
    icon_url TEXT,
    color_code VARCHAR(7),
    is_active BOOLEAN DEFAULT TRUE
);
```

#### Posts Table
```sql
CREATE TABLE posts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES post_categories(id),
    title VARCHAR(200),
    content TEXT NOT NULL,
    post_type VARCHAR(20) DEFAULT 'general', -- 'general', 'event', 'alert', 'marketplace', 'lost_found'
    privacy_level VARCHAR(20) DEFAULT 'neighborhood', -- 'neighborhood', 'group', 'public'
    is_pinned BOOLEAN DEFAULT FALSE,
    is_approved BOOLEAN DEFAULT TRUE,
    moderation_status VARCHAR(20) DEFAULT 'approved', -- 'pending', 'approved', 'rejected'
    moderated_by UUID REFERENCES users(id),
    moderated_at TIMESTAMP,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Post Media Table
```sql
CREATE TABLE post_media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
    media_type VARCHAR(20), -- 'image', 'video', 'audio', 'document'
    file_url TEXT NOT NULL,
    thumbnail_url TEXT,
    file_size INTEGER,
    mime_type VARCHAR(100),
    duration_seconds INTEGER, -- for video/audio
    dimensions JSONB, -- {"width": 1920, "height": 1080}
    upload_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Post Reactions Table
```sql
CREATE TABLE post_reactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    reaction_type VARCHAR(20) DEFAULT 'like', -- 'like', 'love', 'laugh', 'angry', 'sad'
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(post_id, user_id)
);
```

#### Post Comments Table
```sql
CREATE TABLE post_comments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    post_id UUID REFERENCES posts(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    parent_comment_id UUID REFERENCES post_comments(id),
    content TEXT NOT NULL,
    is_approved BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

### Events & Calendar Tables

#### Events Table
```sql
CREATE TABLE events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organizer_id UUID REFERENCES users(id) ON DELETE CASCADE,
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    event_type VARCHAR(50), -- 'social', 'educational', 'business', 'emergency', 'religious'
    venue_name VARCHAR(200),
    venue_address TEXT,
    venue_latitude DECIMAL(10, 8),
    venue_longitude DECIMAL(11, 8),
    start_datetime TIMESTAMP NOT NULL,
    end_datetime TIMESTAMP,
    max_attendees INTEGER,
    current_attendees INTEGER DEFAULT 0,
    is_free BOOLEAN DEFAULT TRUE,
    ticket_price DECIMAL(10, 2),
    registration_required BOOLEAN DEFAULT FALSE,
    registration_deadline TIMESTAMP,
    is_cancelled BOOLEAN DEFAULT FALSE,
    cancellation_reason TEXT,
    cover_image_url TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Event RSVPs Table
```sql
CREATE TABLE event_rsvps (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID REFERENCES events(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    rsvp_status VARCHAR(20) DEFAULT 'going', -- 'going', 'maybe', 'not_going'
    plus_ones INTEGER DEFAULT 0,
    special_requests TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(event_id, user_id)
);
```

### Marketplace & Services Tables

#### Marketplace Categories Table
```sql
CREATE TABLE marketplace_categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    parent_id INTEGER REFERENCES marketplace_categories(id),
    description TEXT,
    icon_url TEXT,
    is_active BOOLEAN DEFAULT TRUE
);
```

#### Marketplace Listings Table
```sql
CREATE TABLE marketplace_listings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    seller_id UUID REFERENCES users(id) ON DELETE CASCADE,
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    category_id INTEGER REFERENCES marketplace_categories(id),
    title VARCHAR(200) NOT NULL,
    description TEXT,
    listing_type VARCHAR(20), -- 'sell', 'buy', 'service', 'job'
    price DECIMAL(12, 2),
    price_type VARCHAR(20) DEFAULT 'fixed', -- 'fixed', 'negotiable', 'free', 'hourly'
    condition_type VARCHAR(20), -- 'new', 'used_like_new', 'used_good', 'used_fair'
    availability_status VARCHAR(20) DEFAULT 'available', -- 'available', 'pending', 'sold', 'expired'
    location_details TEXT,
    contact_preference VARCHAR(20) DEFAULT 'in_app', -- 'in_app', 'phone', 'email'
    is_featured BOOLEAN DEFAULT FALSE,
    expires_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Marketplace Listing Media Table
```sql
CREATE TABLE marketplace_listing_media (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    listing_id UUID REFERENCES marketplace_listings(id) ON DELETE CASCADE,
    media_url TEXT NOT NULL,
    media_type VARCHAR(20) DEFAULT 'image',
    display_order INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Service Providers Table
```sql
CREATE TABLE service_providers (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    business_name VARCHAR(200),
    business_description TEXT,
    service_categories JSONB, -- array of service types
    years_experience INTEGER,
    hourly_rate DECIMAL(8, 2),
    availability_schedule JSONB, -- weekly schedule
    service_radius_km INTEGER DEFAULT 5,
    is_verified BOOLEAN DEFAULT FALSE,
    license_number VARCHAR(100),
    insurance_details TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Service Reviews Table
```sql
CREATE TABLE service_reviews (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    service_provider_id UUID REFERENCES service_providers(id) ON DELETE CASCADE,
    reviewer_id UUID REFERENCES users(id) ON DELETE CASCADE,
    listing_id UUID REFERENCES marketplace_listings(id),
    rating INTEGER CHECK (rating >= 1 AND rating <= 5),
    review_text TEXT,
    service_date DATE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(service_provider_id, reviewer_id, listing_id)
);
```

### Messaging & Communication Tables

#### Conversations Table
```sql
CREATE TABLE conversations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_type VARCHAR(20), -- 'direct', 'group', 'neighborhood'
    title VARCHAR(200), -- for group chats
    description TEXT,
    neighborhood_id UUID REFERENCES neighborhoods(id),
    created_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    last_message_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Conversation Participants Table
```sql
CREATE TABLE conversation_participants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member', -- 'admin', 'moderator', 'member'
    joined_at TIMESTAMP DEFAULT NOW(),
    left_at TIMESTAMP,
    is_muted BOOLEAN DEFAULT FALSE,
    last_read_at TIMESTAMP,
    UNIQUE(conversation_id, user_id)
);
```

#### Messages Table
```sql
CREATE TABLE messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    conversation_id UUID REFERENCES conversations(id) ON DELETE CASCADE,
    sender_id UUID REFERENCES users(id) ON DELETE CASCADE,
    message_type VARCHAR(20) DEFAULT 'text', -- 'text', 'image', 'audio', 'video', 'location', 'system'
    content TEXT,
    media_url TEXT,
    reply_to_message_id UUID REFERENCES messages(id),
    is_edited BOOLEAN DEFAULT FALSE,
    edited_at TIMESTAMP,
    is_deleted BOOLEAN DEFAULT FALSE,
    deleted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Message Read Receipts Table
```sql
CREATE TABLE message_read_receipts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    message_id UUID REFERENCES messages(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    read_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(message_id, user_id)
);
```

### Groups & Communities Tables

#### Groups Table
```sql
CREATE TABLE groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    group_type VARCHAR(50), -- 'interest', 'support', 'business', 'sports', 'hobby'
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    privacy_level VARCHAR(20) DEFAULT 'public', -- 'public', 'private', 'invite_only'
    created_by UUID REFERENCES users(id),
    cover_image_url TEXT,
    max_members INTEGER,
    current_members INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Group Memberships Table
```sql
CREATE TABLE group_memberships (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    group_id UUID REFERENCES groups(id) ON DELETE CASCADE,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(20) DEFAULT 'member', -- 'admin', 'moderator', 'member'
    membership_status VARCHAR(20) DEFAULT 'active', -- 'pending', 'active', 'banned'
    joined_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(group_id, user_id)
);
```

### Safety & Alerts Tables

#### Safety Alerts Table
```sql
CREATE TABLE safety_alerts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID REFERENCES users(id) ON DELETE CASCADE,
    neighborhood_id UUID REFERENCES neighborhoods(id) ON DELETE CASCADE,
    alert_type VARCHAR(50), -- 'crime', 'accident', 'suspicious_activity', 'emergency', 'traffic'
    severity_level VARCHAR(20), -- 'low', 'medium', 'high', 'critical'
    title VARCHAR(200) NOT NULL,
    description TEXT NOT NULL,
    incident_location TEXT,
    incident_latitude DECIMAL(10, 8),
    incident_longitude DECIMAL(11, 8),
    incident_datetime TIMESTAMP,
    verification_status VARCHAR(20) DEFAULT 'unverified', -- 'unverified', 'verified', 'false_report'
    verified_by UUID REFERENCES users(id),
    verification_count INTEGER DEFAULT 0,
    is_resolved BOOLEAN DEFAULT FALSE,
    resolution_notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
```

#### Alert Verifications Table
```sql
CREATE TABLE alert_verifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id UUID REFERENCES safety_alerts(id) ON DELETE CASCADE,
    verifier_id UUID REFERENCES users(id) ON DELETE CASCADE,
    verification_type VARCHAR(20), -- 'confirm', 'deny', 'additional_info'
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(alert_id, verifier_id)
);
```

### Notification & News Tables

#### Notification Preferences Table
```sql
CREATE TABLE notification_preferences (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    notification_type VARCHAR(50), -- 'posts', 'events', 'messages', 'safety_alerts', 'marketplace'
    delivery_method VARCHAR(20), -- 'push', 'email', 'sms'
    is_enabled BOOLEAN DEFAULT TRUE,
    frequency VARCHAR(20) DEFAULT 'immediate', -- 'immediate', 'hourly', 'daily', 'weekly'
    quiet_hours_start TIME,
    quiet_hours_end TIME,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, notification_type, delivery_method)
);
```

#### Notifications Table
```sql
CREATE TABLE notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    notification_type VARCHAR(50),
    title VARCHAR(200),
    message TEXT,
    data JSONB, -- additional structured data
    delivery_method VARCHAR(20),
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'sent', 'delivered', 'failed'
    scheduled_at TIMESTAMP DEFAULT NOW(),
    sent_at TIMESTAMP,
    read_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### News Sources Table
```sql
CREATE TABLE news_sources (
    id SERIAL PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    description TEXT,
    website_url TEXT,
    rss_feed_url TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    coverage_areas JSONB, -- array of neighborhood IDs
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### News Articles Table
```sql
CREATE TABLE news_articles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id INTEGER REFERENCES news_sources(id),
    title VARCHAR(500) NOT NULL,
    summary TEXT,
    content TEXT,
    author VARCHAR(200),
    published_at TIMESTAMP,
    image_url TEXT,
    external_url TEXT,
    tags JSONB,
    neighborhood_relevance JSONB, -- array of neighborhood IDs
    is_featured BOOLEAN DEFAULT FALSE,
    view_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Moderation & Administration Tables

#### Moderation Reports Table
```sql
CREATE TABLE moderation_reports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    reporter_id UUID REFERENCES users(id) ON DELETE CASCADE,
    reported_user_id UUID REFERENCES users(id),
    content_type VARCHAR(50), -- 'post', 'comment', 'message', 'listing', 'user_profile'
    content_id UUID,
    report_reason VARCHAR(100), -- 'spam', 'harassment', 'inappropriate_content', 'fake_news', 'scam'
    description TEXT,
    status VARCHAR(20) DEFAULT 'pending', -- 'pending', 'reviewed', 'action_taken', 'dismissed'
    reviewed_by UUID REFERENCES users(id),
    action_taken VARCHAR(100),
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### User Restrictions Table
```sql
CREATE TABLE user_restrictions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    restriction_type VARCHAR(50), -- 'warning', 'temporary_ban', 'permanent_ban', 'feature_restriction'
    reason TEXT,
    restricted_features JSONB, -- array of features user can't access
    imposed_by UUID REFERENCES users(id),
    starts_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Administrators Table
```sql
CREATE TABLE administrators (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    admin_level VARCHAR(20), -- 'super_admin', 'neighborhood_admin', 'content_moderator'
    permissions JSONB,
    assigned_neighborhoods JSONB, -- array of neighborhood IDs for local admins
    assigned_by UUID REFERENCES users(id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

### Analytics & Metrics Tables

#### User Activities Table
```sql
CREATE TABLE user_activities (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    activity_type VARCHAR(50), -- 'login', 'post_create', 'message_send', 'event_rsvp', etc.
    entity_type VARCHAR(50), -- 'post', 'event', 'message', 'listing'
    entity_id UUID,
    metadata JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
```

#### Business Metrics Table
```sql
CREATE TABLE business_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    metric_type VARCHAR(50), -- 'daily_active_users', 'posts_created', 'messages_sent'
    metric_value DECIMAL(15, 2),
    dimensions JSONB, -- additional breakdowns like neighborhood_id, user_type
    date_recorded DATE,
    created_at TIMESTAMP DEFAULT NOW()
);
```

## Critical Indexes for Performance

```sql
-- User and authentication indexes
CREATE INDEX CONCURRENTLY idx_users_phone_number ON users(phone_number);
CREATE INDEX CONCURRENTLY idx_users_email ON users(email);
CREATE INDEX CONCURRENTLY idx_user_sessions_user_id ON user_sessions(user_id);

-- Geolocation indexes
CREATE INDEX CONCURRENTLY idx_user_locations_gist 
ON user_locations USING GIST(ST_Point(longitude, latitude));
CREATE INDEX CONCURRENTLY idx_neighborhoods_center 
ON neighborhoods USING GIST(ST_Point(center_longitude, center_latitude));

-- Social feed indexes
CREATE INDEX CONCURRENTLY idx_posts_neighborhood_created 
ON posts(neighborhood_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_posts_active 
ON posts(neighborhood_id, created_at DESC) 
WHERE is_approved = true AND moderation_status = 'approved';

-- Messaging indexes
CREATE INDEX CONCURRENTLY idx_messages_conversation_created 
ON messages(conversation_id, created_at DESC);
CREATE INDEX CONCURRENTLY idx_conversation_participants_user 
ON conversation_participants(user_id);

-- Marketplace indexes
CREATE INDEX CONCURRENTLY idx_marketplace_location_category 
ON marketplace_listings USING GIST(ST_Point(longitude, latitude)) 
WHERE availability_status = 'available';

-- Events indexes
CREATE INDEX CONCURRENTLY idx_events_neighborhood_date 
ON events(neighborhood_id, start_datetime);

-- Analytics indexes
CREATE INDEX CONCURRENTLY idx_user_activities_user_type 
ON user_activities(user_id, activity_type, created_at);
```

## Data Retention Policies

```sql
-- Automatically clean up old data
-- User activities older than 2 years
DELETE FROM user_activities WHERE created_at < NOW() - INTERVAL '2 years';

-- OTP verifications older than 24 hours
DELETE FROM otp_verifications WHERE created_at < NOW() - INTERVAL '24 hours';

-- Inactive user sessions older than 90 days
DELETE FROM user_sessions WHERE expires_at < NOW() - INTERVAL '90 days';

-- Expired marketplace listings older than 30 days
DELETE FROM marketplace_listings 
WHERE availability_status = 'expired' 
AND expires_at < NOW() - INTERVAL '30 days';
```

## Backup Strategy

- **Automated Snapshots**: Every 6 hours
- **Transaction Log Backup**: Every 15 minutes
- **Cross-Region Replication**: Enabled
- **Retention**: 30 days for operational backups
- **Long-term Archival**: Annual snapshots to S3 Glacier