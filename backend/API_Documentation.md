# HoodMe API Documentation

## Overview
This document outlines the complete API structure for HoodMe, including REST endpoints, WebSocket events, and authentication flows.

## Base Configuration

### API Base URL
```
Production: https://api.HoodMe.com
Staging: https://staging-api.HoodMe.com
Development: http://localhost:3000
```

### API Versioning
```
Current Version: v1
Base Path: /api/v1/
```

### Authentication
All protected endpoints require a Bearer token in the Authorization header:
```http
Authorization: Bearer <jwt_token>
```

## Authentication Endpoints

### POST /api/v1/auth/register
Register a new user account.

**Request Body:**
```json
{
  "phone_number": "+2348123456789",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "password": "securePassword123",
  "preferred_language": "en"
}
```

**Response (201):**
```json
{
  "success": true,
  "message": "Registration successful. Please verify your phone number.",
  "data": {
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "verification_required": true,
    "contact_method": "phone"
  }
}
```

### POST /api/v1/auth/verify-otp
Verify OTP for phone/email verification.

**Request Body:**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "otp_code": "123456",
  "contact_method": "phone"
}
```

**Response (200):**
```json
{
  "success": true,
  "message": "Verification successful",
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "first_name": "John",
      "last_name": "Doe",
      "email": "user@example.com",
      "phone_number": "+2348123456789",
      "is_verified": true,
      "profile_picture_url": null,
      "preferred_language": "en"
    }
  }
}
```

### POST /api/v1/auth/login
Login with phone/email and password.

**Request Body:**
```json
{
  "login": "+2348123456789", // phone or email
  "password": "securePassword123",
  "device_id": "device_12345",
  "device_type": "mobile"
}
```

**Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
    "expires_in": 900,
    "user": {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "first_name": "John",
      "last_name": "Doe",
      "neighborhoods": [
        {
          "id": "660f9500-f39c-51e5-b827-557766551111",
          "name": "Victoria Island",
          "is_primary": true
        }
      ]
    }
  }
}
```

### POST /api/v1/auth/refresh-token
Refresh access token using refresh token.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

### POST /api/v1/auth/logout
Logout and invalidate tokens.

**Request Body:**
```json
{
  "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

## User Management Endpoints

### GET /api/v1/users/profile
Get current user profile.

**Response (200):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "first_name": "John",
    "last_name": "Doe",
    "email": "user@example.com",
    "phone_number": "+2348123456789",
    "profile_picture_url": "https://cdn.HoodMe.com/users/profile_123.jpg",
    "date_of_birth": "1990-05-15",
    "gender": "male",
    "preferred_language": "en",
    "is_verified": true,
    "created_at": "2024-01-15T10:30:00Z",
    "neighborhoods": [
      {
        "id": "660f9500-f39c-51e5-b827-557766551111",
        "name": "Victoria Island",
        "relationship_type": "resident",
        "is_primary": true,
        "joined_at": "2024-01-15T10:35:00Z"
      }
    ]
  }
}
```

### PUT /api/v1/users/profile
Update user profile.

**Request Body:**
```json
{
  "first_name": "John",
  "last_name": "Doe",
  "date_of_birth": "1990-05-15",
  "gender": "male",
  "preferred_language": "en"
}
```

### GET /api/v1/users/search
Search for users within neighborhoods.

**Query Parameters:**
- `q` (string): Search query
- `neighborhood_id` (UUID): Limit search to specific neighborhood
- `page` (integer): Page number (default: 1)
- `limit` (integer): Items per page (default: 20)

**Response (200):**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "770f9500-f39c-51e5-b827-557766552222",
        "first_name": "Jane",
        "last_name": "Smith",
        "profile_picture_url": "https://cdn.HoodMe.com/users/profile_456.jpg",
        "neighborhoods": ["Victoria Island", "Ikoyi"],
        "mutual_neighbors": 5
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 3,
      "total_items": 45,
      "items_per_page": 20
    }
  }
}
```

## Neighborhood Endpoints

### GET /api/v1/neighborhoods/discover
Discover neighborhoods based on location.

**Query Parameters:**
- `lat` (float): Latitude
- `lng` (float): Longitude
- `radius` (integer): Search radius in kilometers (default: 5)

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "660f9500-f39c-51e5-b827-557766551111",
      "name": "Victoria Island",
      "description": "Business and residential area in Lagos",
      "center_latitude": 6.4281,
      "center_longitude": 3.4219,
      "member_count": 1250,
      "distance_km": 0.8,
      "is_verified": true,
      "lga": {
        "name": "Lagos Island",
        "state": "Lagos"
      }
    }
  ]
}
```

### POST /api/v1/neighborhoods/join
Join a neighborhood.

**Request Body:**
```json
{
  "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111",
  "relationship_type": "resident", // resident, worker, visitor
  "verification_method": "gps", // gps, referral, manual
  "is_primary": true
}
```

### GET /api/v1/neighborhoods/{id}/feed
Get neighborhood feed.

**Query Parameters:**
- `category` (string): Filter by post category
- `page` (integer): Page number
- `limit` (integer): Items per page

**Response (200):**
```json
{
  "success": true,
  "data": {
    "posts": [
      {
        "id": "880f9500-f39c-51e5-b827-557766553333",
        "title": "Community Meeting Tonight",
        "content": "Join us for the monthly community meeting at 7 PM...",
        "category": {
          "id": 1,
          "name": "General",
          "color_code": "#3498db"
        },
        "author": {
          "id": "550e8400-e29b-41d4-a716-446655440000",
          "first_name": "John",
          "last_name": "Doe",
          "profile_picture_url": "https://cdn.HoodMe.com/users/profile_123.jpg"
        },
        "media": [
          {
            "type": "image",
            "url": "https://cdn.HoodMe.com/posts/image_789.jpg",
            "thumbnail_url": "https://cdn.HoodMe.com/posts/thumb_789.jpg"
          }
        ],
        "reactions_count": {
          "like": 15,
          "love": 3,
          "total": 18
        },
        "comments_count": 7,
        "user_reaction": "like",
        "created_at": "2024-01-20T14:30:00Z",
        "updated_at": "2024-01-20T14:30:00Z"
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 5,
      "total_items": 89
    }
  }
}
```

## Posts Endpoints

### POST /api/v1/posts
Create a new post.

**Request Body:**
```json
{
  "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111",
  "category_id": 1,
  "title": "Lost Cat - Please Help",
  "content": "My cat went missing yesterday evening. Orange tabby, responds to 'Whiskers'...",
  "post_type": "lost_found",
  "privacy_level": "neighborhood",
  "media_urls": [
    "https://cdn.HoodMe.com/temp/upload_abc123.jpg"
  ]
}
```

**Response (201):**
```json
{
  "success": true,
  "data": {
    "id": "990f9500-f39c-51e5-b827-557766554444",
    "title": "Lost Cat - Please Help",
    "content": "My cat went missing yesterday evening...",
    "created_at": "2024-01-20T15:45:00Z"
  }
}
```

### POST /api/v1/posts/{id}/react
React to a post.

**Request Body:**
```json
{
  "reaction_type": "like" // like, love, laugh, angry, sad
}
```

### GET /api/v1/posts/{id}/comments
Get post comments.

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "aaf9500-f39c-51e5-b827-557766555555",
      "content": "I saw a cat matching this description near the park.",
      "author": {
        "id": "bbf9500-f39c-51e5-b827-557766556666",
        "first_name": "Sarah",
        "last_name": "Johnson",
        "profile_picture_url": "https://cdn.HoodMe.com/users/profile_789.jpg"
      },
      "created_at": "2024-01-20T16:15:00Z",
      "replies": []
    }
  ]
}
```

### POST /api/v1/posts/{id}/comments
Add a comment to a post.

**Request Body:**
```json
{
  "content": "I'll keep an eye out for your cat!",
  "parent_comment_id": null // For replies
}
```

## Events Endpoints

### GET /api/v1/events
Get events in neighborhood.

**Query Parameters:**
- `neighborhood_id` (UUID): Filter by neighborhood
- `date_range` (string): Format "YYYY-MM-DD,YYYY-MM-DD"
- `event_type` (string): Filter by event type

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "ccf9500-f39c-51e5-b827-557766557777",
      "title": "Neighborhood Clean-up Day",
      "description": "Join us for our monthly neighborhood clean-up...",
      "event_type": "social",
      "organizer": {
        "id": "550e8400-e29b-41d4-a716-446655440000",
        "first_name": "John",
        "last_name": "Doe"
      },
      "venue": {
        "name": "Community Center",
        "address": "123 Main Street, Victoria Island",
        "latitude": 6.4281,
        "longitude": 3.4219
      },
      "start_datetime": "2024-01-25T09:00:00Z",
      "end_datetime": "2024-01-25T12:00:00Z",
      "max_attendees": 50,
      "current_attendees": 23,
      "is_free": true,
      "user_rsvp_status": "going",
      "cover_image_url": "https://cdn.HoodMe.com/events/cover_123.jpg"
    }
  ]
}
```

### POST /api/v1/events
Create a new event.

**Request Body:**
```json
{
  "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111",
  "title": "Block Party",
  "description": "Annual block party with food, music, and fun activities...",
  "event_type": "social",
  "venue_name": "Community Park",
  "venue_address": "456 Park Avenue, Victoria Island",
  "venue_latitude": 6.4285,
  "venue_longitude": 3.4225,
  "start_datetime": "2024-02-15T18:00:00Z",
  "end_datetime": "2024-02-15T22:00:00Z",
  "max_attendees": 100,
  "is_free": true,
  "registration_required": false
}
```

### POST /api/v1/events/{id}/rsvp
RSVP to an event.

**Request Body:**
```json
{
  "rsvp_status": "going", // going, maybe, not_going
  "plus_ones": 2,
  "special_requests": "Vegetarian meal please"
}
```

## Marketplace Endpoints

### GET /api/v1/marketplace/listings
Get marketplace listings.

**Query Parameters:**
- `category` (string): Filter by category
- `lat` (float): Latitude for location-based search
- `lng` (float): Longitude for location-based search
- `radius` (integer): Search radius in kilometers
- `listing_type` (string): sell, buy, service, job
- `price_min` (float): Minimum price
- `price_max` (float): Maximum price

**Response (200):**
```json
{
  "success": true,
  "data": {
    "listings": [
      {
        "id": "ddf9500-f39c-51e5-b827-557766558888",
        "title": "iPhone 13 - Excellent Condition",
        "description": "Selling my iPhone 13, 128GB, used for 1 year...",
        "listing_type": "sell",
        "price": 450000.00,
        "price_type": "negotiable",
        "condition_type": "used_like_new",
        "category": {
          "id": 1,
          "name": "Electronics"
        },
        "seller": {
          "id": "eef9500-f39c-51e5-b827-557766559999",
          "first_name": "Michael",
          "last_name": "Adebayo",
          "profile_picture_url": "https://cdn.HoodMe.com/users/profile_321.jpg",
          "rating": 4.8,
          "reviews_count": 15
        },
        "media": [
          {
            "url": "https://cdn.HoodMe.com/listings/phone_001.jpg",
            "type": "image"
          }
        ],
        "location_details": "Victoria Island area",
        "distance_km": 1.2,
        "created_at": "2024-01-18T10:00:00Z"
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 8,
      "total_items": 156
    }
  }
}
```

### POST /api/v1/marketplace/listings
Create a marketplace listing.

**Request Body:**
```json
{
  "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111",
  "category_id": 1,
  "title": "Laptop for Sale",
  "description": "Dell XPS 13, 2 years old, excellent for work...",
  "listing_type": "sell",
  "price": 250000.00,
  "price_type": "fixed",
  "condition_type": "used_good",
  "location_details": "Ikoyi area",
  "contact_preference": "in_app",
  "media_urls": [
    "https://cdn.HoodMe.com/temp/upload_def456.jpg"
  ]
}
```

## Messaging Endpoints

### GET /api/v1/messaging/conversations
Get user's conversations.

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "fff9500-f39c-51e5-b827-55776655aaaa",
      "conversation_type": "direct",
      "title": null,
      "participants": [
        {
          "id": "550e8400-e29b-41d4-a716-446655440000",
          "first_name": "John",
          "last_name": "Doe",
          "profile_picture_url": "https://cdn.HoodMe.com/users/profile_123.jpg",
          "is_online": true,
          "last_seen": "2024-01-20T17:30:00Z"
        }
      ],
      "last_message": {
        "id": "ggg9500-f39c-51e5-b827-55776655bbbb",
        "content": "Thanks for the help with the event planning!",
        "sender_id": "550e8400-e29b-41d4-a716-446655440000",
        "message_type": "text",
        "created_at": "2024-01-20T17:25:00Z"
      },
      "unread_count": 2,
      "last_message_at": "2024-01-20T17:25:00Z",
      "created_at": "2024-01-15T14:20:00Z"
    }
  ]
}
```

### POST /api/v1/messaging/conversations
Start a new conversation.

**Request Body:**
```json
{
  "conversation_type": "direct", // direct, group
  "participant_ids": ["770f9500-f39c-51e5-b827-557766552222"],
  "title": null, // Required for group conversations
  "initial_message": "Hi! I saw your post about the lost cat."
}
```

### GET /api/v1/messaging/conversations/{id}/messages
Get messages in a conversation.

**Query Parameters:**
- `page` (integer): Page number
- `limit` (integer): Messages per page (default: 50)
- `before` (string): Get messages before this timestamp

**Response (200):**
```json
{
  "success": true,
  "data": {
    "messages": [
      {
        "id": "hhh9500-f39c-51e5-b827-55776655cccc",
        "sender_id": "550e8400-e29b-41d4-a716-446655440000",
        "message_type": "text",
        "content": "Thanks for the help with the event planning!",
        "media_url": null,
        "reply_to_message_id": null,
        "is_edited": false,
        "read_by": [
          {
            "user_id": "770f9500-f39c-51e5-b827-557766552222",
            "read_at": "2024-01-20T17:26:00Z"
          }
        ],
        "created_at": "2024-01-20T17:25:00Z"
      }
    ],
    "pagination": {
      "current_page": 1,
      "total_pages": 3,
      "has_more": true
    }
  }
}
```

### POST /api/v1/messaging/conversations/{id}/messages
Send a message.

**Request Body:**
```json
{
  "message_type": "text", // text, image, audio, video, location
  "content": "Sure, I'd be happy to help!",
  "media_url": null, // Required for non-text messages
  "reply_to_message_id": null
}
```

## Safety & Alerts Endpoints

### GET /api/v1/safety/alerts
Get safety alerts in neighborhood.

**Query Parameters:**
- `neighborhood_id` (UUID): Filter by neighborhood
- `severity` (string): low, medium, high, critical
- `alert_type` (string): crime, accident, suspicious_activity, emergency, traffic

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "iii9500-f39c-51e5-b827-55776655dddd",
      "title": "Suspicious Activity Reported",
      "description": "Unknown person trying door handles on Maple Street...",
      "alert_type": "suspicious_activity",
      "severity_level": "medium",
      "reporter": {
        "id": "jjj9500-f39c-51e5-b827-55776655eeee",
        "first_name": "Anonymous", // May be anonymized
        "verification_level": "verified_resident"
      },
      "incident_location": "Maple Street, Victoria Island",
      "incident_latitude": 6.4280,
      "incident_longitude": 3.4220,
      "incident_datetime": "2024-01-20T15:30:00Z",
      "verification_status": "verified",
      "verification_count": 3,
      "is_resolved": false,
      "created_at": "2024-01-20T15:45:00Z"
    }
  ]
}
```

### POST /api/v1/safety/alerts
Create a safety alert.

**Request Body:**
```json
{
  "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111",
  "alert_type": "suspicious_activity",
  "severity_level": "medium",
  "title": "Suspicious Activity",
  "description": "Saw someone trying car door handles on Oak Street...",
  "incident_location": "Oak Street, Victoria Island",
  "incident_latitude": 6.4275,
  "incident_longitude": 3.4215,
  "incident_datetime": "2024-01-20T18:00:00Z"
}
```

### POST /api/v1/safety/alerts/{id}/verify
Verify a safety alert.

**Request Body:**
```json
{
  "verification_type": "confirm", // confirm, deny, additional_info
  "notes": "I also witnessed this incident around the same time."
}
```

## Notification Endpoints

### GET /api/v1/notifications
Get user notifications.

**Query Parameters:**
- `unread_only` (boolean): Only show unread notifications
- `type` (string): Filter by notification type

**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "kkk9500-f39c-51e5-b827-55776655ffff",
      "notification_type": "new_post",
      "title": "New post in Victoria Island",
      "message": "John Doe posted about the community meeting",
      "data": {
        "post_id": "880f9500-f39c-51e5-b827-557766553333",
        "neighborhood_id": "660f9500-f39c-51e5-b827-557766551111"
      },
      "is_read": false,
      "created_at": "2024-01-20T16:30:00Z"
    }
  ]
}
```

### PUT /api/v1/notifications/read-all
Mark all notifications as read.

## File Upload Endpoints

### POST /api/v1/uploads/images
Upload an image file.

**Request:** Multipart form data
- `file`: Image file (max 10MB)
- `type`: upload type (profile, post, listing, event)

**Response (200):**
```json
{
  "success": true,
  "data": {
    "url": "https://cdn.HoodMe.com/uploads/image_xyz789.jpg",
    "thumbnail_url": "https://cdn.HoodMe.com/uploads/thumb_xyz789.jpg",
    "file_size": 2048576,
    "dimensions": {
      "width": 1920,
      "height": 1080
    }
  }
}
```

## WebSocket Events

### Connection
```javascript
const socket = io('wss://api.HoodMe.com/messaging', {
  auth: {
    token: 'Bearer <jwt_token>'
  }
});
```

### Messaging Events
```javascript
// Join conversation room
socket.emit('join_conversation', { conversation_id: 'xxx-xxx-xxx' });

// Send message
socket.emit('send_message', {
  conversation_id: 'xxx-xxx-xxx',
  message_type: 'text',
  content: 'Hello!'
});

// Listen for new messages
socket.on('new_message', (message) => {
  console.log('New message:', message);
});

// Typing indicators
socket.emit('typing_start', { conversation_id: 'xxx-xxx-xxx' });
socket.emit('typing_stop', { conversation_id: 'xxx-xxx-xxx' });

// User presence
socket.on('user_online', (data) => {
  console.log('User came online:', data.user_id);
});
```

### Real-time Notifications
```javascript
const notificationSocket = io('wss://api.HoodMe.com/notifications');

notificationSocket.on('new_notification', (notification) => {
  console.log('New notification:', notification);
});

notificationSocket.on('safety_alert', (alert) => {
  console.log('Safety alert:', alert);
});
```

## Error Responses

### Standard Error Format
```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "The provided data is invalid",
    "details": {
      "phone_number": ["Phone number must be in Nigerian format"],
      "email": ["Email address is required"]
    }
  },
  "request_id": "req_123456789"
}
```

### Common Error Codes
- `VALIDATION_ERROR` (400): Invalid request data
- `UNAUTHORIZED` (401): Invalid or missing authentication
- `FORBIDDEN` (403): Insufficient permissions
- `NOT_FOUND` (404): Resource not found
- `RATE_LIMITED` (429): Too many requests
- `INTERNAL_ERROR` (500): Server error

## Rate Limiting

### Standard Limits
- **Authentication endpoints**: 10 requests per minute
- **General API**: 100 requests per minute
- **File uploads**: 20 requests per minute
- **WebSocket connections**: 5 connections per user

### Headers
```http
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 85
X-RateLimit-Reset: 1640995200
```

## Pagination

### Standard Pagination Response
```json
{
  "pagination": {
    "current_page": 1,
    "total_pages": 10,
    "total_items": 195,
    "items_per_page": 20,
    "has_next": true,
    "has_previous": false
  }
}
```

### Cursor-based Pagination (for real-time feeds)
```json
{
  "pagination": {
    "next_cursor": "eyJjcmVhdGVkX2F0IjoiMjAyNC0wMS0yMFQxNjo...",
    "has_more": true
  }
}
```