# TrueShotOdds Authentication Backend

A comprehensive Spring Boot application focused on user authentication and session management with Redis-based distributed sessions.

## Features

### Authentication & Session Management
- Session-based authentication (no JWT tokens)
- Spring Security with session management
- HTTP sessions for user state management
- Session timeout configuration
- CSRF protection enabled
- Cookie-based session handling
- Secure session configuration (HttpOnly, Secure flags)
- Session fixation protection
- Concurrent session control (limit sessions per user)

### Redis Session Storage
- Spring Session Data Redis for distributed session management
- Redis connection configuration with connection pooling
- Session serialization/deserialization handling
- Session expiration aligned with Redis TTL
- Failover handling for Redis connectivity issues

### User Management
- User registration with email verification
- User login/logout functionality
- Password reset via email
- User profile management (basic CRUD)
- Account activation/deactivation
- Password strength validation
- User roles and basic authorization
- Account lockout after failed login attempts

## Tech Stack

- **Framework**: Spring Boot 3.5.6
- **Java**: 21+
- **Build Tool**: Maven
- **Database**: MySQL 8.0
- **Cache/Session**: Redis 7.0
- **Security**: Spring Security 6
- **API Documentation**: OpenAPI/Swagger
- **Containerization**: Docker & Docker Compose
- **Testing**: JUnit 5, Mockito, TestContainers

## Project Structure

```
├── src/
│   ├── main/
│   │   ├── java/dev/wenslo/trueshotodds/
│   │   │   ├── config/          # Configuration classes
│   │   │   ├── controller/      # REST controllers
│   │   │   ├── dto/            # Data Transfer Objects
│   │   │   ├── entity/         # JPA entities
│   │   │   ├── exception/      # Custom exceptions
│   │   │   ├── repository/     # Data repositories
│   │   │   ├── security/       # Security configuration
│   │   │   └── service/        # Business logic
│   │   └── resources/
│   │       ├── db/migration/   # Flyway migrations
│   │       └── application*.properties
│   └── test/                   # Test classes
├── docker/                     # Docker configuration
├── docker-compose.yml
├── Dockerfile
└── README.md
```

## Quick Start

### Prerequisites

- Java 21+
- Maven 3.6+
- Docker & Docker Compose
- MySQL 8.0 (if running locally)
- Redis 7.0 (if running locally)

### Option 1: Docker Compose (Recommended)

1. **Clone and navigate to the project**
   ```bash
   git clone <repository-url>
   cd trueshotodds_springboot_v2
   ```
   or you can use IntelliJ's built-in features.
   - Head to the top of an already existing project
   - Go to Git -> Clone and in the URL box, paste the HTTPS URL of this repository.

2. **Configure environment variables**
   Create a `.env` file in the root directory. Use the .env.example as a reference:
   ```env
   BASE_URL=http://localhost:5173
   CORS_ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3001,http://127.0.0.1:5173,http://127.0.0.1:3001
   
   SPRING_REDIS_HOST=localhost
   SPRING_REDIS_PORT=6379

   RDS_HOSTNAME=your-database-host.amazonaws.com
   RDS_PORT=3306
   RDS_DB_NAME=your_database_name
   SPRING_DATASOURCE_USERNAME=your_db_username
   SPRING_DATASOURCE_PASSWORD=your_secure_db_password

   MAIL_HOST=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USERNAME=your_email@gmail.com
   MAIL_PASSWORD=your_app_specific_password
   MAIL_FROM=noreply@yourdomain.com

   GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
   GOOGLE_CLIENT_SECRET=your_google_client_secret
   ```

3. **Start the application**
   ```bash
   docker-compose up -d
   ```

4. **Verify the application is running**
   ```bash
   curl http://localhost:8080/actuator/health
   ```

### Option 2: Local Development

1. **Start MySQL and Redis**
   ```bash
   # MySQL in Docker
   docker run -d --name mysql -e MYSQL_ROOT_PASSWORD=password -e MYSQL_DATABASE=trueshot_odds -p 3306:3306 mysql:8.0
   
   # Redis in Docker
   docker run -d --name redis -p 6379:6379 redis:7.0-alpine
   docker compose up redis -d
   ```

2. **Configure application properties**
   Update `src/main/resources/application.properties` with your database and mail settings.

3. **Create an application-dev.properties file in src/main/resources**
   Use this application-dev.properties file to differentiate any settings with development versus production.

4. **Build and run**
   ```bash
   mvn clean install
   mvn spring-boot:run -Dspring-boot.run.profiles=dev
   ```

## API Endpoints

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/register` | Register a new user |
| POST | `/api/auth/login` | User login |
| POST | `/api/auth/logout` | User logout |
| GET | `/api/auth/me` | Get current user profile |
| POST | `/api/auth/forgot-password` | Request password reset |
| POST | `/api/auth/reset-password` | Reset password with token |
| PUT | `/api/auth/change-password` | Change password (authenticated) |
| GET | `/api/auth/session` | Check session status |
| GET | `/api/auth/verify-email` | Verify email address |

### Profile Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/profile` | Get user profile details |
| PUT | `/api/profile/preferences` | Update user preferences |

## API Documentation

Once the application is running, access the Swagger UI at:
- http://localhost:8080/swagger-ui.html

## Database Schema

### Users Table
- User authentication and profile information
- Email verification and account status
- Failed login attempts and account lockout

### Subscriptions Table
- User subscription plans and billing information
- Support for different billing cycles
- Expiration and cancellation handling

### User Preferences Table
- Notification and email update preferences
- Extensible for future preference types

### Password Reset Tokens Table
- Secure token-based password reset
- Automatic token expiration and cleanup

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MAIL_USERNAME` | SMTP username for sending emails | - |
| `MAIL_PASSWORD` | SMTP password/app password | - |
| `MAIL_FROM` | From email address | noreply@trueshotodds.com |
| `BASE_URL` | Application base URL | http://localhost:8080 |

### Application Properties

Key configuration properties:

```properties
# Database
spring.datasource.url=jdbc:mysql://localhost:3306/trueshot_odds
spring.datasource.username=root
spring.datasource.password=password

# Redis Session Store
spring.data.redis.host=localhost
spring.data.redis.port=6379
spring.session.store-type=redis
spring.session.timeout=1800s

# Security
app.security.max-failed-login-attempts=5
app.security.account-lockout-minutes=15
app.security.password-reset-token-expiration-hours=1
```

## Testing

### Run Tests

```bash
# Unit tests
mvn test

# Integration tests
mvn verify

# With coverage
mvn test jacoco:report
```

### Test Configuration

Tests use:
- H2 in-memory database
- Embedded Redis (or mocked)
- Spring Security Test
- TestContainers for integration tests

## Security Features

### Session Security
- HttpOnly cookies
- Secure flag for HTTPS
- CSRF protection
- Session fixation protection
- Concurrent session control

### Authentication Security
- BCrypt password encoding (strength 12)
- Account lockout after failed attempts
- Email verification required
- Password strength validation
- Secure password reset flow

### API Security
- Rate limiting on authentication endpoints
- Comprehensive input validation
- SQL injection prevention
- XSS protection headers

## Monitoring & Health Checks

### Health Endpoints
- `/actuator/health` - Application health
- `/actuator/info` - Application info
- `/actuator/metrics` - Application metrics

### Logging
- Structured logging with correlation IDs
- Audit logging for authentication events
- Configurable log levels by environment

## Production Deployment

### Pre-deployment Checklist

1. **Security Configuration**
   - Set `server.servlet.session.cookie.secure=true` for HTTPS
   - Configure proper CORS settings
   - Set up SSL/TLS certificates

2. **Database**
   - Set up MySQL with proper indexing
   - Configure connection pooling
   - Set up automated backups

3. **Redis**
   - Configure Redis persistence
   - Set up Redis clustering for high availability
   - Configure memory policies

4. **Monitoring**
   - Set up application monitoring
   - Configure log aggregation
   - Set up alerting for critical errors


## Troubleshooting

### Common Issues

1. **Session not persisting**
   - Check Redis connection
   - Check database connection
   - Verify session timeout configuration
   - Check cookie settings

2. **Email not sending**
   - Verify SMTP credentials
   - Check firewall settings
   - Ensure app passwords are used for Gmail

3. **Database connection issues**
   - Check MySQL is running
   - Verify connection string
   - Check firewall/network settings

### Debug Mode

Enable debug logging:
```properties
logging.level.dev.wenslo.trueshotodds=DEBUG
logging.level.org.springframework.security=DEBUG
logging.level.org.springframework.session=DEBUG
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

## License

This project is licensed under the Apache 2.0 License - see the LICENSE file for details.

## Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the API documentation at `/swagger-ui.html`